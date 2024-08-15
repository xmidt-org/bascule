// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"

	"go.uber.org/multierr"
)

// Approver is a strategy for determining if a given token represents
// adequate permissions to access a resource.  Approvers are used
// as part of bascule's authorization workflow.
type Approver[R any] interface {
	// Approve tests if a given token holds the correct permissions to
	// access a given resource.  If this method needs to access external
	// systems, it should pass the supplied context to honor context
	// cancelation semantics.
	//
	// If this method doesn't support the given token, it should return nil.
	Approve(ctx context.Context, resource R, token Token) error
}

// ApproverFunc is a closure type that implements Approver.
type ApproverFunc[R any] func(context.Context, R, Token) error

func (af ApproverFunc[R]) Approve(ctx context.Context, resource R, token Token) error {
	return af(ctx, resource, token)
}

// Approvers is an aggregate Approver.
type Approvers[R any] []Approver[R]

// Append tacks on one or more approvers to this collection.  The possibly
// new Approvers instance is returned.  The semantics of this method are
// the same as the built-in append.
func (as Approvers[R]) Append(more ...Approver[R]) Approvers[R] {
	return append(as, more...)
}

// Approve requires all approvers in this sequence to allow access.  This
// method supplies a logical AND.
//
// Because authorization can be arbitrarily expensive, execution halts at the first failed
// authorization attempt.
func (as Approvers[R]) Approve(ctx context.Context, resource R, token Token) error {
	for _, a := range as {
		if err := a.Approve(ctx, resource, token); err != nil {
			return err
		}
	}

	return nil
}

type requireAny[R any] struct {
	a Approvers[R]
}

// Approve returns nil at the first approver that returns nil, i.e. accepts the access.
// Otherwise, this method returns an aggregate error of all the authorization errors.
func (ra requireAny[R]) Approve(ctx context.Context, resource R, token Token) error {
	var err error
	for _, a := range ra.a {
		authErr := a.Approve(ctx, resource, token)
		if authErr == nil {
			return nil
		}

		err = multierr.Append(err, authErr)
	}

	return err
}

// Any returns an Approver which is a logical OR:  each approver is executed in
// order, and any approver that allows access results in an immediate return.  The
// returned Approver's state is distinct and is unaffected by subsequent changes
// to the Approvers set.
//
// Any error returns from the returned Approver will be an aggregate of all the errors
// returned from each element.
func (as Approvers[R]) Any() Approver[R] {
	return requireAny[R]{
		a: append(
			make(Approvers[R], 0, len(as)),
			as...,
		),
	}
}
