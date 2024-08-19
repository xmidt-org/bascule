// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"errors"
	"net/http"
	"strings"
)

const (
	// WWWAuthenticateHeader is the HTTP header used for StatusUnauthorized challenges
	// when encountered by the Middleware.
	//
	// This value is used by default when no header is supplied to Challenges.WriteHeader.
	WWWAuthenticateHeader = "WWW-Authenticate"
)

var (
	// ErrInvalidChallengeScheme indicates that a scheme was improperly formatted.  Usually,
	// this methods the scheme was either blank or contained whitespace.
	ErrInvalidChallengeScheme = errors.New("Invalid challenge auth scheme")

	// ErrInvalidChallengeParameter indicates that an attempt was made to an a challenge
	// auth parameter that wasn't validly formatted.  Usually, this means that the
	// name contained whitespace.
	ErrInvalidChallengeParameter = errors.New("Invalid challenge auth parameter")

	// ErrReservedChallengeParameter indicates that an attempt was made to add a
	// challenge auth parameter that was reserved by the RFC.
	ErrReservedChallengeParameter = errors.New("Reserved challenge auth parameter")
)

// reservedChallengeParameterNames holds the names of reserved challenge auth parameters
// that cannot be added to a ChallengeParameters.
var reservedChallengeParameterNames = map[string]bool{
	"realm":   true,
	"token68": true,
}

// ChallengeParameters holds the set of parameters.  The zero value of this
// type is ready to use.  This type handles writing parameters as well as
// provides commonly used parameter names for convenience.
type ChallengeParameters struct {
	names, values []string
	byName        map[string]int // the parameter index
}

// Len returns the number of name/value pairs contained in these parameters.
func (cp *ChallengeParameters) Len() int {
	return len(cp.names)
}

// Set sets the value of a parameter.  If a parameter was already set, it is
// ovewritten.
//
// If the parameter name is invalid, this method raises an error.
func (cp *ChallengeParameters) Set(name, value string) (err error) {
	switch {
	case len(name) == 0:
		err = ErrInvalidChallengeParameter

	case fastContainsSpace(name):
		err = ErrInvalidChallengeParameter

	case reservedChallengeParameterNames[name]:
		err = ErrReservedChallengeParameter

	default:
		if i, exists := cp.byName[name]; exists {
			cp.values[i] = value
		} else {
			if cp.byName == nil {
				cp.byName = make(map[string]int)
			}

			cp.byName[name] = len(cp.names)
			cp.names = append(cp.names, name)
			cp.values = append(cp.values, value)
		}
	}

	return
}

// Charset sets a charset auth parameter.  Basic auth is the main scheme
// that uses this.
func (cp *ChallengeParameters) Charset(value string) error {
	return cp.Set("charset", value)
}

// Write formats this challenge to the given builder.
func (cp *ChallengeParameters) Write(o *strings.Builder) {
	for i := 0; i < len(cp.names); i++ {
		if i > 0 {
			o.WriteString(", ")
		}

		o.WriteString(cp.names[i])
		o.WriteString(`="`)
		o.WriteString(cp.values[i])
		o.WriteRune('"')
	}
}

// String returns the RFC 7235 format of these parameters.
func (cp *ChallengeParameters) String() string {
	var o strings.Builder
	cp.Write(&o)
	return o.String()
}

// NewChallengeParameters creates a ChallengeParameters from a sequence of name/value pairs.
// The strings are expected to be in name, value, name, value, ... sequence.  If the number
// of strings is odd, then the last parameter will have a blank value.
//
// If any error occurs while setting parameters, execution is halted and that
// error is returned.
func NewChallengeParameters(s ...string) (cp ChallengeParameters, err error) {
	for i, j := 0, 1; err == nil && i < len(s); i, j = i+2, j+2 {
		if j < len(s) {
			err = cp.Set(s[i], s[j])
		} else {
			err = cp.Set(s[i], "")
		}
	}

	return
}

// Challenge represets an HTTP authentication challenge, as defined by RFC 7235.
type Challenge struct {
	// Scheme is the name of scheme supplied in the challenge.  This field is required.
	Scheme Scheme

	// Realm is the name of the realm for the challenge.  This field is
	// optional, but it is HIGHLY recommended to set it to something useful
	// to a client.
	Realm string

	// Token68 controls whether the token68 flag is written in the challenge.
	Token68 bool

	// Parameters are the optional auth parameters.
	Parameters ChallengeParameters
}

// Write formats this challenge to the given builder.  Any error halts
// formatting and that error is returned.
func (c Challenge) Write(o *strings.Builder) (err error) {
	s := string(c.Scheme)
	switch {
	case len(s) == 0:
		err = ErrInvalidChallengeScheme

	case fastContainsSpace(s):
		err = ErrInvalidChallengeScheme

	default:
		o.WriteString(s)
		if len(c.Realm) > 0 {
			o.WriteString(` realm="`)
			o.WriteString(c.Realm)
			o.WriteRune('"')
		}

		if c.Token68 {
			o.WriteString(" token68")
		}

		if c.Parameters.Len() > 0 {
			o.WriteRune(' ')
			c.Parameters.Write(o)
		}
	}

	return
}

// NewBasicChallenge is a convenience for creating a Challenge for basic auth.
//
// Although realm is optional, it is HIGHLY recommended to set it to something
// recognizable for a client.
func NewBasicChallenge(realm string, UTF8 bool) (c Challenge, err error) {
	c = Challenge{
		Scheme: SchemeBasic,
		Realm:  realm,
	}

	if UTF8 {
		err = c.Parameters.Charset("UTF-8")
	}

	return
}

// Challenges represents a sequence of challenges to associated with
// a StatusUnauthorized response.
type Challenges []Challenge

// Append appends challenges to this set.  The semantics of this
// method are the same as the built-in append.
func (chs Challenges) Append(ch ...Challenge) Challenges {
	return append(chs, ch...)
}

// WriteHeader inserts one Http authenticate header per challenge in this set.
// If this set is empty, the given http.Header is not modified.
//
// The name is used as the header name for each header this method writes.
// Typically, this will be WWW-Authenticate or Proxy-Authenticate.  If name
// is blank, WWWAuthenticateHeaderName is used.
//
// If any challenge returns an error during formatting, execution is
// halted and that error is returned.
func (chs Challenges) WriteHeader(name string, h http.Header) error {
	if len(name) == 0 {
		name = WWWAuthenticateHeader
	}

	var o strings.Builder
	for _, ch := range chs {
		err := ch.Write(&o)
		if err != nil {
			return err
		}

		h.Add(name, o.String())
		o.Reset()
	}

	return nil
}
