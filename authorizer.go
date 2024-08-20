// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
)

var (
	// ErrUnauthorized is a general error indicating that a token was unauthorized
	// for a particular resource.  Most authorizers and approvers should use this
	// error or wrap this error to indicate failed authorization.
	ErrUnauthorized = errors.New("unauthorized")
)

// AuthorizeEvent represents the result of bascule's authorize workflow.
type AuthorizeEvent[R any] struct {
	// Resource is the thing the token wants to access.  This
	// field is always set.
	Resource R

	// Token is the token that either was or was not authorized.
	// This field is always set.
	Token Token

	// Err is the error that resulted from authorization.  This field will be
	// nil for a successful authorization..
	Err error
}

// AuthorizerOption is a configurable option for an Authorizer.
type AuthorizerOption[S any] interface {
	apply(*Authorizer[S]) error
}

type authorizerOptionFunc[S any] func(*Authorizer[S]) error

//nolint:unused
func (aof authorizerOptionFunc[S]) apply(a *Authorizer[S]) error { return aof(a) }

// WithAuthorizeListeners adds listeners to the Authorizer being built.
// Multiple calls for this option are cumulative.
func WithAuthorizeListeners[R any](more ...Listener[AuthorizeEvent[R]]) AuthorizerOption[R] {
	return authorizerOptionFunc[R](
		func(a *Authorizer[R]) error {
			a.listeners = a.listeners.Append(more...)
			return nil
		},
	)
}

// WithAuthorizeListenerFuncs is a closure variant of WithAuthorizeListeners.
func WithAuthorizeListenerFuncs[R any](more ...ListenerFunc[AuthorizeEvent[R]]) AuthorizerOption[R] {
	return authorizerOptionFunc[R](
		func(a *Authorizer[R]) error {
			a.listeners = a.listeners.AppendFunc(more...)
			return nil
		},
	)
}

// WithApprovers adds approvers to the Authorizer being built.
// Multiple calls for this option are cumulative.
func WithApprovers[R any](more ...Approver[R]) AuthorizerOption[R] {
	return authorizerOptionFunc[R](
		func(a *Authorizer[R]) error {
			a.approvers = a.approvers.Append(more...)
			return nil
		},
	)
}

// WithApproverFuncs is a closure variant of WithApprovers that eases the
// syntactical pain of dealing with approvers that are functions.
func WithApproverFuncs[R any](more ...ApproverFunc[R]) AuthorizerOption[R] {
	return authorizerOptionFunc[R](
		func(a *Authorizer[R]) error {
			a.approvers = a.approvers.AppendFunc(more...)
			return nil
		},
	)
}

// NewAuthorizer constructs an Authorizer workflow using the supplied options.
//
// If no options are supplied, the returned Authorizer will authorize all tokens
// to access any resources.
func NewAuthorizer[R any](opts ...AuthorizerOption[R]) (a *Authorizer[R], err error) {
	a = new(Authorizer[R])
	for i := 0; err == nil && i < len(opts); i++ {
		err = opts[i].apply(a)
	}

	return
}

// Authorizer represents the full bascule authorizer workflow.  An authenticated
// token is required as the starting point for authorization.
type Authorizer[R any] struct {
	listeners Listeners[AuthorizeEvent[R]]
	approvers Approvers[R]
}

// Authorize implements the bascule authorization workflow for a particular type of
// resource.  The following steps are performed:
//
// (1) Each approver is invoked, and all approvers must approve access
// (2) An AuthorizeEvent is dispatched to any listeners with the result
//
// Any error that occurred during authorization is returned.
func (a *Authorizer[R]) Authorize(ctx context.Context, resource R, token Token) (err error) {
	err = a.approvers.Approve(ctx, resource, token)
	a.listeners.OnEvent(AuthorizeEvent[R]{
		Resource: resource,
		Token:    token,
		Err:      err,
	})

	return
}
