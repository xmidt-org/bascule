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

// Authorizers is a collection of Authorizers.
type Authorizers[R any] []Authorizer[R]

// Add appends authorizers to this aggregate Authorizers.
func (as *Authorizers[R]) Add(a ...Authorizer[R]) {
	if *as == nil {
		*as = make(Authorizers[R], len(a))
	}

	*as = append(*as, a...)
}

// Authorize requires all authorizers in this sequence to allow access.  This
// method supplies a logical AND.
//
// Because authorization can be arbitrarily expensive, execution halts at the first failed
// authorization attempt.
func (as Authorizers[R]) Authorize(ctx context.Context, token Token, resource R) error {
	for _, a := range as {
		if err := a.Authorize(ctx, token, resource); err != nil {
			return err
		}
	}

	return nil
}

type requireAny[R any] struct {
	a Authorizers[R]
}

// Authorize returns nil at the first authorizer that returns nil, i.e. accepts the access.
// Otherwise, this method returns an aggregate error of all the authorization errors.
func (ra requireAny[R]) Authorize(ctx context.Context, token Token, resource R) error {
	var err error
	for _, a := range ra.a {
		authErr := a.Authorize(ctx, token, resource)
		if authErr == nil {
			return nil
		}

		err = multierr.Append(err, authErr)
	}

	return err
}

// Any returns an Authorizer which is a logical OR:  each authorizer is executed in
// order, and any authorizer that allows access results in an immediate return.  The
// returned Authorizer's state is distinct and is unaffected by subsequent changes
// to the Authorizers set.
//
// Any error returns from the returned Authorizer will be an aggregate of all the errors
// returned from each element.
func (as Authorizers[R]) Any() Authorizer[R] {
	return requireAny[R]{
		a: append(
			make(Authorizers[R], 0, len(as)),
			as...,
		),
	}
}
