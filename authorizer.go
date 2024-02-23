// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"

	"go.uber.org/multierr"
)

// Authorizer is a strategy for determining if a given token represents
// adequate permissions to access a resource.
type Authorizer[R any] interface {
	// Authorize tests if a given token holds the correct permissions to
	// access a given resource.  If this method needs to access external
	// systems, it should pass the supplied context to honor context
	// cancelation semantics.
	//
	// If this method doesn't support the given token, it should return nil.
	Authorize(ctx context.Context, token Token, resource R) error
}

// Authorizers is a collection of Authorizers that exposes factory methods
// for creating Authorizer instances joined by boolean operations.
type Authorizers[R any] []Authorizer[R]

// Add appends authorizers to this aggregate Authorizers.
func (as *Authorizers[R]) Add(a ...Authorizer[R]) {
	if *as == nil {
		*as = make(Authorizers[R], len(a))
	}

	*as = append(*as, a...)
}

// Clone creates a distinct Authorizers instance with the same sequence
// of Authorizer strategies.
func (as Authorizers[R]) Clone() Authorizers[R] {
	clone := make(Authorizers[R], 0, len(as))
	clone = append(clone, as...)
	return clone
}

type requireAll[R any] struct {
	authorizers Authorizers[R]
}

func (ra requireAll[R]) Authorize(ctx context.Context, token Token, resource R) error {
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
func (as Authorizers[R]) RequireAll() Authorizer[R] {
	return requireAll[R]{
		authorizers: as.Clone(),
	}
}

type requireAny[R any] struct {
	authorizers Authorizers[R]
}

func (ra requireAny[R]) Authorize(ctx context.Context, token Token, resource R) error {
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
func (as Authorizers[R]) RequireAny() Authorizer[R] {
	return requireAny[R]{
		authorizers: as.Clone(),
	}
}
