// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"

	"go.uber.org/multierr"
)

// Validator represents a general strategy for validating tokens.  Token validation
// typically happens during authentication, but it can also happen during parsing
// if a caller uses NewValidatingTokenParser.
type Validator interface {
	// Validate validates a token.  If this validator needs to interact
	// with external systems, the supplied context can be passed to honor
	// cancelation semantics.
	Validate(context.Context, Token) error
}

// Validators is an aggregate Validator.
type Validators []Validator

// Add appends validators to this aggregate Validators.
func (vs *Validators) Add(v ...Validator) {
	if *vs == nil {
		*vs = make(Validators, len(v))
	}

	*vs = append(*vs, v...)
}

func (vs Validators) Clone() Validators {
	clone := make(Validators, 0, len(vs))
	clone = append(clone, vs...)
	return clone
}

// Validate applies each validator in sequence.  All validators are run, and
// any errors are glued together via multierr.
func (vs Validators) Validate(ctx context.Context, token Token) (err error) {
	for _, v := range vs {
		err = multierr.Append(err, v.Validate(ctx, token))
	}

	return
}
