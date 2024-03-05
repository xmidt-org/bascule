// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/xmidt-org/bascule/v1"
)

// Claims exposes standard JWT claims from a Token.
type Claims interface {
	// Audience returns the aud field of the JWT.
	Audience() []string

	// Expiration returns the exp field of the JWT.
	Expiration() time.Time

	// IssuedAt returns the iat field of the JWT.
	IssuedAt() time.Time

	// Issuer returns the iss field of the JWT.
	Issuer() string

	// JwtID returns the jti field of the JWT.
	JwtID() string

	// NotBefore returns the nbf field of the JWT.
	NotBefore() time.Time

	// Subject returns the sub field of the JWT.  For tokens that
	// implement this interface, this method returns the same value
	// as tne Principal method.
	Subject() string
}

// Token is the interface implemented by JWT-based tokens supplied by this package.
// User-defined claims can be accessed through the bascule.Attributes interface.
//
// Note that the Princpal method returns the same value as the Subject claim.
type Token interface {
	bascule.Token
	bascule.Attributes
	Claims
}

// token is the internal implementation of the JWT Token interface.  It fronts
// a lestrrat-go Token.
type token struct {
	jwt.Token
}

func (t *token) Principal() string {
	return t.Token.Subject()
}

// tokenParser is the canonical parser for bascule that deals with JWTs.
type tokenParser struct {
	options []jwt.ParseOption
}

// NewTokenParser constructs a parser using the supplied set of parse options.
// The returned parser will produce tokens that implement the Token interface
// in this package.
func NewTokenParser(options ...jwt.ParseOption) (bascule.TokenParser, error) {
	return &tokenParser{
		options: append(
			make([]jwt.ParseOption, 0, len(options)),
			options...,
		),
	}, nil
}

func (tp *tokenParser) Parse(_ context.Context, c bascule.Credentials) (bascule.Token, error) {
	jwtToken, err := jwt.ParseString(c.Value, tp.options...)
	if err != nil {
		return nil, err
	}

	return &token{
		Token: jwtToken,
	}, nil
}
