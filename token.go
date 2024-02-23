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

type validatingTokenParser struct {
	parser     TokenParser
	validators Validators
}

func (v *validatingTokenParser) Parse(ctx context.Context, c Credentials) (token Token, err error) {
	token, err = v.parser.Parse(ctx, c)
	if err == nil {
		err = v.validators.Validate(ctx, token)
	}

	return
}

// NewValidatingTokenParser decorates a TokenParser such that the given validators are
// applied after Parse is called.  The returned TokenParser will handle the workflow of
// (1) invoking tp.Parse, (2) applying validators if t.Parse succeeded.
//
// If v is an empty slice, this function returns tp unmodified.
func NewValidatingTokenParser(tp TokenParser, v ...Validator) TokenParser {
	if len(v) == 0 {
		return tp
	}

	return &validatingTokenParser{
		parser:     tp,
		validators: Validators(v).Clone(),
	}
}

// TokenParsers is a registry of parsers based on credential schemes.
// The zero value of this type is valid and ready to use.
type TokenParsers map[Scheme]TokenParser

// Clone produces a distinct copy of this instance.
func (tp TokenParsers) Clone() TokenParsers {
	clone := make(TokenParsers, len(tp))
	for k, v := range tp {
		clone[k] = v
	}

	return clone
}

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
