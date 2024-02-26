// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
)

// Contexter is anything that logically holds a context.  For example, *http.Request
// implements this interface.
type Contexter interface {
	Context() context.Context
}

type credentialsContextKey struct{}

// GetCredentials examines the context and returns the credentials used to
// build the Token.  If no credentials are in the context, this function
// returns false.
func GetCredentials(ctx context.Context) (c Credentials, found bool) {
	c, found = ctx.Value(credentialsContextKey{}).(Credentials)
	return
}

// GetCredentialsFrom uses the context held by src to obtain credentials.
// As with GetCredentials, if no credentials are found this function returns false.
func GetCredentialsFrom(src Contexter) (Credentials, bool) {
	return GetCredentials(src.Context())
}

// WithCredentials constructs a new context with the supplied credentials.
func WithCredentials(ctx context.Context, c Credentials) context.Context {
	return context.WithValue(
		ctx,
		credentialsContextKey{},
		c,
	)
}

type tokenContextKey struct{}

// GetToken retrieves a Token from a context.  If not token is in the context,
// this function returns false.
func GetToken(ctx context.Context) (t Token, found bool) {
	t, found = ctx.Value(tokenContextKey{}).(Token)
	return
}

// GetTokenFrom uses the context held by src to obtain a Token.  As with GetToken,
// if no token is found this function returns false.
func GetTokenFrom(src Contexter) (Token, bool) {
	return GetToken(src.Context())
}

// WithToken constructs a new context with the supplied token.
func WithToken(ctx context.Context, t Token) context.Context {
	return context.WithValue(
		ctx,
		tokenContextKey{},
		t,
	)
}
