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

// token is the internal implementation of the JWT Token interface.  It fronts
// a lestrrat-go Token.
type token struct {
	jwt.Token
}

func (t *token) Principal() string {
	return t.Token.Subject()
}

// tokenParser is the canonical parser for bascule that deals with JWTs.
// This parser does not use the source.
type tokenParser struct {
	options []jwt.ParseOption
}

// NewTokenParser constructs a parser using the supplied set of parse options.
func NewTokenParser(options ...jwt.ParseOption) (bascule.TokenParser[string], error) {
	return &tokenParser{
		options: append(
			make([]jwt.ParseOption, 0, len(options)),
			options...,
		),
	}, nil
}

// Parse parses the value as a JWT, using the parsing options passed to NewTokenParser.
// The returned Token will implement the bascule.Attributes and Claims interfaces.
func (tp *tokenParser) Parse(ctx context.Context, value string) (bascule.Token, error) {
	jwtToken, err := jwt.ParseString(value, tp.options...)
	if err != nil {
		return nil, err
	}

	return &token{
		Token: jwtToken,
	}, nil
}
