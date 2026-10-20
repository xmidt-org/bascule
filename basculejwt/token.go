// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/xmidt-org/bascule"
)

// CapabilitiesKey is the JWT claims key where capabilities are expected.
const CapabilitiesKey = "capabilities"

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
	jwt jwt.Token
}

func (t token) Audience() []string {
	v, _ := t.jwt.Audience()

	return v
}

func (t token) Expiration() time.Time {
	v, _ := t.jwt.Expiration()

	return v
}

func (t token) IssuedAt() time.Time {
	v, _ := t.jwt.IssuedAt()

	return v
}

func (t token) Issuer() string {
	v, _ := t.jwt.Issuer()

	return v
}

func (t token) JwtID() string {
	v, _ := t.jwt.JwtID()

	return v
}

func (t token) NotBefore() time.Time {
	v, _ := t.jwt.NotBefore()

	return v
}

func (t token) Subject() string {
	v, _ := t.jwt.Subject()

	return v
}

func (t token) Principal() string {
	v, _ := t.jwt.Subject()

	return v
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
// The Token is nil whenever the error is not.
func (tp *tokenParser) Parse(ctx context.Context, value string) (bascule.Token, error) {
	t, err := tp.ParseWithDetails(ctx, value)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// ParseWithDetails is Parse, except that a JWT whose signature verified but
// whose claims were rejected, e.g. one that has expired, is returned along with
// the error.  The signature is what makes what the token says about who sent it
// believable.  That token is for recording who was turned away and nothing
// else: it has been rejected, and the error is always non-nil.  Any other
// failure, including every signature failure, returns a nil Token.
func (tp *tokenParser) ParseWithDetails(ctx context.Context, value string) (bascule.Token, error) {
	// the caller's context governs anything jwx reaches out to, such as a key
	// provider fetching from a remote key set.  tp.options is not modified: it
	// is shared by every call, so the option is appended to a copy.
	options := make([]jwt.ParseOption, 0, len(tp.options)+2)
	options = append(options, tp.options...)
	options = append(options, jwt.WithContext(ctx))

	jwtToken, err := jwt.ParseString(value, options...)
	if err != nil {
		// jwx checks the signature before it checks the claims, so a claims
		// failure means the signature was good.  jwx discards the token it
		// built in that case, so it is read again without the claim checks.
		if errors.Is(err, jwt.ValidationError{}) {
			verified, verr := jwt.ParseString(value, append(options, jwt.WithValidate(false))...)
			if verr == nil {
				return &token{jwt: verified}, translate(err)
			}
		}

		return nil, translate(err)
	}

	return &token{
		jwt: jwtToken,
	}, nil
}

var _ bascule.DetailedTokenParser[string] = (*tokenParser)(nil)
