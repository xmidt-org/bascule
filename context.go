// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
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

type tokenContextKey struct{}

// Get retrieves a Token from a context.  If not token is in the context,
// this function returns false.
func Get(ctx context.Context) (t Token, found bool) {
	t, found = ctx.Value(tokenContextKey{}).(Token)
	return
}

// GetFrom uses the context held by src to obtain a Token.  As with GetToken,
// if no token is found this function returns false.
func GetFrom(src Contexter) (Token, bool) {
	return Get(src.Context())
}

// WithToken constructs a new context with the supplied token.
func WithToken(ctx context.Context, t Token) context.Context {
	return context.WithValue(
		ctx,
		tokenContextKey{},
		t,
	)
}
