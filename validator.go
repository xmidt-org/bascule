// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
)

// Validator represents a general strategy for validating tokens.  Token validation
// typically happens during authentication, but it can also happen during parsing
// if a caller uses NewValidatingTokenParser.
type Validator interface {
	// Validate validates a token.  If this validator needs to interact
	// with external systems, the supplied context can be passed to honor
	// cancelation semantics.
	//
	// This method may be passed a token that it doesn't support, e.g. a Basic
	// validator can be passed a JWT token.  In that case, this method should
	// simply return nil.
	Validate(context.Context, Token) error
}

// ValidatorFunc is a closure type that implements Validator.
type ValidatorFunc func(context.Context, Token) error

func (vf ValidatorFunc) Validate(ctx context.Context, token Token) error {
	return vf(ctx, token)
}

// Validators is an aggregate Validator.
type Validators []Validator

// Add appends validators to this aggregate Validators.
func (vs *Validators) Add(v ...Validator) {
	if *vs == nil {
		*vs = make(Validators, 0, len(v))
	}

	*vs = append(*vs, v...)
}

// Validate applies each validator in sequence.  Execution stops at the first validator
// that returns an error, and that error is returned.  If all validators return nil,
// this method returns nil, indicating the Token is valid.
func (vs Validators) Validate(ctx context.Context, token Token) error {
	for _, v := range vs {
		if err := v.Validate(ctx, token); err != nil {
			return err
		}
	}

	return nil
}
