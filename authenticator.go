// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "context"

// AuthenticateEvent represents the result of bascule's authenticate workflow.
type AuthenticateEvent[S any] struct {
	// Source is the object that was parsed to produce the token.
	// This field is always set.
	Source S

	// Token is the token that resulted from parsing the source.  This field
	// will only be set if parsing was successful.
	Token Token

	// Err is the error that resulted from authentication.  This field will be
	// nil for a successful authentication.
	Err error
}

// AuthenticatorOption is a configurable option for an Authenticator.
type AuthenticatorOption[S any] interface {
	apply(*Authenticator[S]) error
}

type authenticatorOptionFunc[S any] func(*Authenticator[S]) error

func (aof authenticatorOptionFunc[S]) apply(a *Authenticator[S]) error { return aof(a) }

// WithAuthenticateListeners adds listeners to the Authenticator being built.
// Multiple calls for this option are cumulative.
func WithAuthenticateListeners[S any](more ...Listener[AuthenticateEvent[S]]) AuthenticatorOption[S] {
	return authenticatorOptionFunc[S](
		func(a *Authenticator[S]) error {
			a.listeners = a.listeners.Append(more...)
			return nil
		},
	)
}

// WithTokenParsers adds token parsers to the Authenticator being built.
// Multiple calls for this option are cumulative.
func WithTokenParsers[S any](more ...TokenParser[S]) AuthenticatorOption[S] {
	return authenticatorOptionFunc[S](
		func(a *Authenticator[S]) error {
			a.parsers = a.parsers.Append(more...)
			return nil
		},
	)
}

// WithValidators adds validators to the Authenticator being built.
// Multiple calls for this option are cumulative.
func WithValidators[S any](more ...Validator[S]) AuthenticatorOption[S] {
	return authenticatorOptionFunc[S](
		func(a *Authenticator[S]) error {
			a.validators = a.validators.Append(more...)
			return nil
		},
	)
}

// NewAuthenticator constructs an Authenticator workflow using the supplied options.
//
// An empty set of options results in an Authenticator that returns nil Tokens,
// but no authentication errors.
func NewAuthenticator[S any](opts ...AuthenticatorOption[S]) (a *Authenticator[S], err error) {
	a = new(Authenticator[S])
	for i := 0; err == nil && i < len(opts); i++ {
		err = opts[i].apply(a)
	}

	return
}

// Authenticator provides bascule's authentication workflow.  This type handles
// parsing tokens, validating them, and dispatching authentication events to listeners.
type Authenticator[S any] struct {
	listeners  Listeners[AuthenticateEvent[S]]
	parsers    TokenParsers[S]
	validators Validators[S]
}

// Authenticate implements bascule's authentication pipeline.  The following steps are
// performed:
//
// (1) The token is extracted from the source using the configured parser(s)
// (2) The token is validated using any configured validator(s)
// (3) Appropriate events are dispatched to listeners after either of steps (1) or (2)
func (a *Authenticator[S]) Authenticate(ctx context.Context, source S) (token Token, err error) {
	token, err = a.parsers.Parse(ctx, source)
	if err == nil {
		var next Token
		next, err = a.validators.Validate(ctx, source, token)
		if next != nil {
			token = next
		}
	}

	a.listeners.OnEvent(AuthenticateEvent[S]{
		Source: source,
		Token:  token,
		Err:    err,
	})

	return
}
