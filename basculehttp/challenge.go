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

	// RealmParameter is the name of the reserved parameter for realm.
	RealmParameter = "realm"

	// CharsetParameter is the name of the reserved parameter for charset.
	CharsetParameter = "charset"

	// Token68Parameter is the name of the reserved attribute for token68 encoding.
	Token68Parameter = "token68"
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

// blankOrWhitespace tests if v is blank or has any whitespace.  These
// are disallowed by RFC 7235.
func blankOrWhitespace(v string) bool {
	switch {
	case len(v) == 0:
		return true

	case fastContainsSpace(v):
		return true

	default:
		return false
	}
}

// ChallengeParameters holds the set of parameters.  The zero value of this
// type is ready to use.  This type handles writing parameters as well as
// provides commonly used parameter names for convenience.
type ChallengeParameters struct {
	// realm is a reserved parameter.  the spec doesn't require it to be
	// first, but this package always renders it first if supplied.  so it's
	// called out as a separate struct field.
	realm string

	names, values []string
	byName        map[string]int // the parameter indices
}

// Len returns the number of name/value pairs contained in these parameters.
func (cp *ChallengeParameters) Len() (c int) {
	c = len(cp.names)
	if len(cp.realm) > 0 {
		c++
	}

	return
}

// empty is a faster check for emptiness than Len() == 0.
func (cp *ChallengeParameters) empty() bool {
	return len(cp.realm) == 0 && len(cp.names) == 0
}

// unsafeSet performs no validation on the name or value.  This method must
// be called after validation checks or in a context where the name and
// value are known to be safe.  This method also doesn't handle special
// parameters, like the realm.
func (cp *ChallengeParameters) unsafeSet(name, value string) {
	if i, exists := cp.byName[name]; exists {
		cp.values[i] = value
	} else if len(value) > 0 {
		if cp.byName == nil {
			cp.byName = make(map[string]int)
		}

		cp.byName[name] = len(cp.names)
		cp.names = append(cp.names, name)
		cp.values = append(cp.values, value)
	}
}

// Set sets the value of a parameter.  If a parameter was already set, it is
// ovewritten.  The realm may be set via this method, but token68 will be
// rejected as invalid.
//
// This method returns ErrInvalidChallengeParameter if passed a name or a value
// that is blank or contains whitespace.
func (cp *ChallengeParameters) Set(name, value string) (err error) {
	switch {
	case blankOrWhitespace(name):
		err = ErrInvalidChallengeParameter

	case blankOrWhitespace(value):
		err = ErrInvalidChallengeParameter

	case Token68Parameter == strings.ToLower(name):
		err = ErrReservedChallengeParameter

	case RealmParameter == strings.ToLower(name):
		cp.realm = value

	default:
		cp.unsafeSet(name, value)
	}

	return
}

// SetRealm sets a realm auth parameter.  The value cannot be blank or
// contain any whitespace.
func (cp *ChallengeParameters) SetRealm(value string) (err error) {
	if blankOrWhitespace(value) {
		err = ErrInvalidChallengeParameter
	} else {
		cp.realm = value
	}

	return
}

// SetCharset sets a charset auth parameter.  Basic auth is the main scheme
// that uses this.  The value cannot be blank or contain any whitespace.
func (cp *ChallengeParameters) SetCharset(value string) (err error) {
	if blankOrWhitespace(value) {
		err = ErrInvalidChallengeParameter
	} else {
		cp.unsafeSet(CharsetParameter, value)
	}

	return
}

func writeParameter(dst *strings.Builder, name, value string) {
	dst.WriteString(name)
	dst.WriteString(`="`)
	dst.WriteString(value)
	dst.WriteRune('"')
}

// Write formats this challenge to the given builder.
func (cp *ChallengeParameters) Write(dst *strings.Builder) {
	first := true
	if len(cp.realm) > 0 {
		writeParameter(dst, RealmParameter, cp.realm)
		first = false
	}

	for i := 0; i < len(cp.names); i++ {
		if !first {
			dst.WriteString(", ")
		}

		writeParameter(dst, cp.names[i], cp.values[i])
		first = false
	}
}

// String returns the RFC 7235 format of these parameters.
func (cp *ChallengeParameters) String() string {
	var o strings.Builder
	cp.Write(&o)
	return o.String()
}

// NewChallengeParameters creates a ChallengeParameters from a sequence of name/value pairs.
// The strings are expected to be in name1, value1, name2, value2, ..., nameN, valueN  sequence.
// If the number of strings is odd, this method returns an error.  If any duplicate names
// occur, only the last name/value pair is used.
//
// If any error occurs while setting parameters, execution is halted and that
// error is returned.
func NewChallengeParameters(s ...string) (cp ChallengeParameters, err error) {
	if len(s)%2 != 0 {
		err = errors.New("Odd number of challenge parameters")
	}

	for i, j := 0, 1; err == nil && i < len(s); i, j = i+2, j+2 {
		err = cp.Set(s[i], s[j])
	}

	return
}

// Challenge represets an HTTP authentication challenge, as defined by RFC 7235.
type Challenge struct {
	// Scheme is the name of scheme supplied in the challenge.  This field is required.
	Scheme Scheme

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
		o.WriteString(string(c.Scheme))
		if !c.Parameters.empty() {
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
func NewBasicChallenge(realm string, UTF8 bool) (c Challenge) {
	c = Challenge{
		Scheme: SchemeBasic,
	}

	// ignore errors, as this function allows realm to be empty.
	c.Parameters.SetRealm(realm)
	if UTF8 {
		c.Parameters.SetCharset("UTF-8")
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

// WriteHeader write one WWWAuthenticateHeader for each challenge in this
// set.
//
// If any challenge returns an error during formatting, execution is
// halted and that error is returned.
func (chs Challenges) WriteHeader(dst http.Header) error {
	return chs.WriteHeaderCustom(dst, WWWAuthenticateHeader)
}

// WriteHeaderCustom inserts one HTTP authenticate header per challenge in this set.
// If this set is empty, the given http.Header is not modified.
//
// The name is used as the header name for each header this method writes.
// Typically, this will be WWW-Authenticate or Proxy-Authenticate. The name
// parameter is required.
//
// If any challenge returns an error during formatting, execution is
// halted and that error is returned.
func (chs Challenges) WriteHeaderCustom(dst http.Header, name string) error {
	var o strings.Builder
	for _, ch := range chs {
		err := ch.Write(&o)
		if err != nil {
			return err
		}

		dst.Add(name, o.String())
		o.Reset()
	}

	return nil
}
