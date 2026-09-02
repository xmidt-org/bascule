// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/xmidt-org/bascule"
)

// CapabilitiesKey is the JWT claims key where capabilities are expected.
const CapabilitiesKey = "capabilities"

// Claims exposes standard JWT claims from a Token.
type Claims interface {
	// Audience returns the aud field of the JWT.
	Audience() ([]string, bool)

	// Expiration returns the exp field of the JWT.
	Expiration() (time.Time, bool)

	// IssuedAt returns the iat field of the JWT.
	IssuedAt() (time.Time, bool)

	// Issuer returns the iss field of the JWT.
	Issuer() (string, bool)

	// JwtID returns the jti field of the JWT.
	JwtID() (string, bool)

	// NotBefore returns the nbf field of the JWT.
	NotBefore() (time.Time, bool)

	// Subject returns the sub field of the JWT.  For tokens that
	// implement this interface, this method returns the same value
	// as tne Principal method.
	Subject() (string, bool)
}

// token is the internal implementation of the JWT Token interface.  It fronts
// a lestrrat-go Token.
type token struct {
	jwt jwt.Token
}

func (t token) Audience() ([]string, bool) {
	return t.jwt.Audience()
}

func (t token) Expiration() (time.Time, bool) {
	return t.jwt.Expiration()
}

func (t token) IssuedAt() (time.Time, bool) {
	return t.jwt.IssuedAt()
}

func (t token) Issuer() (string, bool) {
	return t.jwt.Issuer()
}

func (t token) JwtID() (string, bool) {
	return t.jwt.JwtID()
}

func (t token) NotBefore() (time.Time, bool) {
	return t.jwt.NotBefore()
}

func (t token) Subject() (string, bool) {
	return t.jwt.Subject()
}

func (t token) Principal() (string, bool) {
	return t.jwt.Subject()
}

func (t token) Capabilities() (caps []string) {
	if v, ok := t.jwt.Field(CapabilitiesKey); ok {
		caps, _ = bascule.GetCapabilities(v)
	}

	return
}

func (t token) Get(key string) (any, bool) {
	return t.jwt.Field(key)
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
// The returned Token will implement the bascule.Attributes, bascule.Capabilities, and Claims interfaces.
func (tp *tokenParser) Parse(ctx context.Context, value string) (bascule.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	jwtToken, err := jwt.ParseString(value, tp.options...)
	if err != nil {
		return nil, err
	}

	return &token{
		jwt: jwtToken,
	}, nil
}
