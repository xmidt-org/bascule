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

// TokenParser produces tokens from credentials.  The original source S of the credentials
// are made available to the parser.
type TokenParser[S any] interface {
	// Parse extracts a Token from a set of credentials.
	Parse(ctx context.Context, source S, c Credentials) (Token, error)
}

// TokenParserFunc is a closure type that implements TokenParser.
type TokenParserFunc[S any] func(context.Context, S, Credentials) (Token, error)

func (tpf TokenParserFunc[S]) Parse(ctx context.Context, source S, c Credentials) (Token, error) {
	return tpf(ctx, source, c)
}

// TokenParsers is a registry of parsers based on credential schemes.
// The zero value of this type is valid and ready to use.
type TokenParsers[S any] map[Scheme]TokenParser[S]

// Register adds or replaces the parser associated with the given scheme.
func (tp *TokenParsers[S]) Register(scheme Scheme, p TokenParser[S]) {
	if *tp == nil {
		*tp = make(TokenParsers[S])
	}

	(*tp)[scheme] = p
}

// Parse chooses a TokenParser based on the Scheme and invokes that
// parser.  If the credential scheme is unsupported, an error is returned.
func (tp TokenParsers[S]) Parse(ctx context.Context, source S, c Credentials) (t Token, err error) {
	if p, ok := tp[c.Scheme]; ok {
		t, err = p.Parse(ctx, source, c)
	} else {
		err = &UnsupportedSchemeError{
			Scheme: c.Scheme,
		}
	}

	return
}
