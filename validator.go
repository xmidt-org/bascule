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
type Validator[T Token] interface {
	// Validate validates a concrete token.  If this validator needs to interact
	// with external systems, the supplied context can be passed to honor
	// cancelation semantics.
	Validate(context.Context, T) error
}

// Validators is an aggregate Validator.
type Validators[T Token] []Validator[T]

// Add appends validators to this aggregate Validators.
func (vs *Validators[T]) Add(v ...Validator[T]) {
	if *vs == nil {
		*vs = make(Validators[T], len(v))
	}

	*vs = append(*vs, v...)
}

func (vs Validators[T]) Clone() Validators[T] {
	clone := make(Validators[T], 0, len(vs))
	clone = append(clone, vs...)
	return clone
}

// Validate applies each validator in sequence.  All validators are run, and
// any errors are glued together via multierr.
func (vs Validators[T]) Validate(ctx context.Context, token T) (err error) {
	for _, v := range vs {
		err = multierr.Append(err, v.Validate(ctx, token))
	}

	return
}
