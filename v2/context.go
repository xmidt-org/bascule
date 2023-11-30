// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "context"

type tokenContextKey struct{}

func GetToken[T Token](ctx context.Context, t *T) (found bool) {
	*t, found = ctx.Value(tokenContextKey{}).(T)
	return
}

func WithToken[T Token](ctx context.Context, t T) context.Context {
	return context.WithValue(
		ctx,
		tokenContextKey{},
		t,
	)
}
