// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
)

// Token is a runtime representation of credentials.  This interface will be further
// customized by infrastructure.
type Token interface {
	// Principal is the security subject of this token, e.g. the user name or other
	// user identifier.
	Principal() string
}

// TokenParser produces tokens from credentials.
type TokenParser interface {
	// Parse turns a Credentials into a token.  This method may validate parts
	// of the credential's value, but should not perform any authentication itself.
	//
	// Some token parsers may interact with external systems, such as databases.  The supplied
	// context should be passed to any calls that might need to honor cancelation semantics.
	Parse(context.Context, Credentials) (Token, error)
}

// TokenParserFunc is a closure type that implements TokenParser.
type TokenParserFunc func(context.Context, Credentials) (Token, error)

func (tpf TokenParserFunc) Parse(ctx context.Context, c Credentials) (Token, error) {
	return tpf(ctx, c)
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
func (tp TokenParsers) Parse(ctx context.Context, c Credentials) (t Token, err error) {
	if p, ok := tp[c.Scheme]; ok {
		t, err = p.Parse(ctx, c)
	} else {
		err = &UnsupportedSchemeError{
			Scheme: c.Scheme,
		}
	}

	return
}
