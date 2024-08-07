// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"strings"
)

const (
	// WwwAuthenticateHeaderName is the HTTP header used for StatusUnauthorized challenges.
	WwwAuthenticateHeaderName = "WWW-Authenticate"

	// DefaultBasicRealm is the realm used for a basic challenge
	// when no realm is supplied.
	DefaultBasicRealm string = "bascule"

	// DefaultBearerRealm is the realm used for a bearer challenge
	// when no realm is supplied.
	DefaultBearerRealm string = "bascule"
)

// Challenge represents a WWW-Authenticate challenge.
type Challenge interface {
	// FormatAuthenticate formats the authenticate string.
	FormatAuthenticate(strings.Builder)
}

// Challenges represents a sequence of challenges to associated with
// a StatusUnauthorized response.
type Challenges []Challenge

// Add appends challenges to this set.
func (chs *Challenges) Add(ch ...Challenge) {
	if *chs == nil {
		*chs = make(Challenges, 0, len(ch))
	}

	*chs = append(*chs, ch...)
}

// WriteHeader inserts one WWW-Authenticate header per challenge in this set.
// If this set is empty, the given http.Header is not modified.
func (chs Challenges) WriteHeader(h http.Header) {
	var o strings.Builder
	for _, ch := range chs {
		ch.FormatAuthenticate(o)
		h.Add(WwwAuthenticateHeaderName, o.String())
		o.Reset()
	}
}

// BasicChallenge represents a WWW-Authenticate basic auth challenge.
type BasicChallenge struct {
	// Scheme is the name of scheme supplied in the challenge.  If this
	// field is unset, BasicScheme is used.
	Scheme Scheme

	// Realm is the name of the realm for the challenge.  If this field
	// is unset, DefaultBasicRealm is used.
	//
	// Note that this field should always be set.  The default isn't very
	// useful outside of development.
	Realm string

	// UTF8 indicates whether "charset=UTF-8" is appended to the challenge.
	// This is the only charset allowed for a Basic challenge.
	UTF8 bool
}

func (bc BasicChallenge) FormatAuthenticate(o strings.Builder) {
	if len(bc.Scheme) > 0 {
		o.WriteString(string(bc.Scheme))
	} else {
		o.WriteString(string(SchemeBasic))
	}

	o.WriteString(` realm="`)
	if len(bc.Realm) > 0 {
		o.WriteString(bc.Realm)
	} else {
		o.WriteString(DefaultBasicRealm)
	}

	o.WriteRune('"')
	if bc.UTF8 {
		o.WriteString(`, charset="UTF-8"`)
	}
}

type BearerChallenge struct {
	// Scheme is the name of scheme supplied in the challenge.  If this
	// field is unset, BearerScheme is used.
	Scheme Scheme

	// Realm is the name of the realm for the challenge.  If this field
	// is unset, DefaultBearerRealm is used.
	//
	// Note that this field should always be set.  The default isn't very
	// useful outside of development.
	Realm string
}

func (bc BearerChallenge) FormatAuthenticate(o strings.Builder) {
	if len(bc.Scheme) > 0 {
		o.WriteString(string(bc.Scheme))
	} else {
		o.WriteString(string(SchemeBearer))
	}

	o.WriteString(` realm="`)
	if len(bc.Realm) > 0 {
		o.WriteString(bc.Realm)
	} else {
		o.WriteString(DefaultBasicRealm)
	}
}
