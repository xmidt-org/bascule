// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"

	"go.uber.org/multierr"
)

// Authorizer is a strategy for determining if a given token represents
// adequate permissions to access a resource.
type Authorizer[T Token, R any] interface {
	// Authorize tests if a given token holds the correct permissions to
	// access a given resource.  If this method needs to access external
	// systems, it should pass the supplied context to honor context
	// cancelation semantics.
	Authorize(ctx context.Context, token T, resource R) error
}

// Authorizers is an aggregate Authorizer for a particular kind of token
// and resource.
type Authorizers[T Token, R any] []Authorizer[T, R]

// Add appends authorizers to this aggregate Authorizers.
func (as *Authorizers[T, R]) Add(a ...Authorizer[T, R]) {
	if *as == nil {
		*as = make(Authorizers[T, R], len(a))
	}

	*as = append(*as, a...)
}

func (as Authorizers[T, R]) Clone() Authorizers[T, R] {
	clone := make(Authorizers[T, R], 0, len(as))
	clone = append(clone, as...)
	return clone
}

type requireAll[T Token, R any] struct {
	authorizers Authorizers[T, R]
}

func (ra requireAll[T, R]) Authorize(ctx context.Context, token T, resource R) error {
	for _, a := range ra.authorizers {
		if err := a.Authorize(ctx, token, resource); err != nil {
			return err
		}
	}

	return nil
}

// RequireAll returns an Authorizer that requires all the authorizers in this
// aggregate to approve access to the resource, i.e. a logical AND.  Any subsequent
// changes to this Authorizers will not be reflected in the returned Authorizer.
//
// The returned Authorizer will invoke all of this sequence's individual authorizers
// in the order they occur in the slice, stopping at the first error.
func (as Authorizers[T, R]) RequireAll() Authorizer[T, R] {
	return requireAll[T, R]{
		authorizers: as.Clone(),
	}
}

type requireAny[T Token, R any] struct {
	authorizers Authorizers[T, R]
}

func (ra requireAny[T, R]) Authorize(ctx context.Context, token T, resource R) error {
	var err error
	for _, a := range ra.authorizers {
		authErr := a.Authorize(ctx, token, resource)
		if authErr == nil {
			return nil
		}

		err = multierr.Append(err, authErr)
	}

	return err
}

// RequireAny returns an Authorizer that only requires one (1) of the authorizers in
// this sequence to approve access to the resource, i.e. a logical OR.  Any subsequent
// changes to this Authorizers will not be reflected in the returned Authorizer.
//
// The return Authorizer will invoke each individual Authorizer in the order in which
// they occur in this sequence, returning a nil error upon the first non-nil error.  If
// all the authorizers returned an error, the returned error will be an aggregate of
// those errors.
func (as Authorizers[T, R]) RequireAny() Authorizer[T, R] {
	return requireAny[T, R]{
		authorizers: as.Clone(),
	}
}
