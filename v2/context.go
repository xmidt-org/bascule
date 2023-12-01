// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "context"

type tokenContextKey struct{}

// GetToken fetches a bascule Token from a context, converting it to
// the given implementing type.  If the token wasn't found in the context
// or if the token was not of the given type, this function returns false.
func GetToken[T Token](ctx context.Context) (t T, ok bool) {
	t, ok = ctx.Value(tokenContextKey{}).(T)
	return
}

// WithToken establishes a Token within a context.  The new context is returned.
func WithToken[T Token](ctx context.Context, t T) context.Context {
	return context.WithValue(
		ctx,
		tokenContextKey{},
		t,
	)
}
