// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "context"

type credentialsContextKey struct{}

// GetCredentials examines the context and returns the credentials used to
// build the Token.  If no credentials are in the context, this function
// returns false.
func GetCredentials(ctx context.Context) (c Credentials, found bool) {
	c, found = ctx.Value(credentialsContextKey{}).(Credentials)
	return
}

// WitheCredentials constructs a new context with the supplied credentials.
func WithCredentials(ctx context.Context, c Credentials) context.Context {
	return context.WithValue(
		ctx,
		credentialsContextKey{},
		c,
	)
}

type tokenContextKey struct{}

// GetToken retrieves a concrete Token from a context.  The supplied pointer
// must be non-nil.  If the context contained a token of the correct type,
// the object pointed to by t is set to that token and this function returns true.
// Otherwise, this function returns false.
func GetToken[T Token](ctx context.Context, t *T) (found bool) {
	*t, found = ctx.Value(tokenContextKey{}).(T)
	return
}

// WithToken constructs a new context with the supplied token.
func WithToken[T Token](ctx context.Context, t T) context.Context {
	return context.WithValue(
		ctx,
		tokenContextKey{},
		t,
	)
}
