// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"errors"
)

// Token is a runtime representation of credentials.  This interface will be further
// customized by infrastructure.
type Token interface {
	// Credentials returns the raw, unparsed information used to produce this Token.
	Credentials() Credentials

	// Principal is the security subject of this token, e.g. the user name or other
	// user identifier.
	Principal() string
}

// TokenParser produces tokens from credentials.
type TokenParser interface {
	// Parse turns a Credentials into a Token.  This method may validate parts
	// of the credential's value, but should not perform any authentication itself.
	Parse(Credentials) (Token, error)
}

// TokenParsers is a registry of parsers based on credential schemes.
// The zero value of this type is valid and ready to use.
type TokenParsers map[Scheme]TokenParser

// Register adds or replaces the parser associated with the given scheme.
func (tp *TokenParsers) Register(scheme Scheme, p TokenParser) {
	if *tp == nil {
		*tp = make(TokenParsers)
	}

	(*tp)[scheme] = p
}

// Parse chooses a TokenParser based on the Scheme and invokes that
// parser.  If the credential scheme is unsupported, an error is returned.
func (tp TokenParsers) Parse(c Credentials) (Token, error) {
	p, ok := tp[c.Scheme]
	if !ok {
		return nil, errors.New("TODO: unsupported credential scheme error")
	}

	return p.Parse(c)
}
