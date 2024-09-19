// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"
	"errors"

	"github.com/xmidt-org/bascule"
)

type matcherValidator[S any] struct {
	cmp   Comparer
	creds Credentials
}

func (mv *matcherValidator[S]) Validate(ctx context.Context, _ S, t bascule.Token) (next bascule.Token, err error) {
	next = t
	password, ok := bascule.GetPassword(t)
	if !ok {
		return
	}

	if digest, exists := mv.creds.Get(ctx, t.Principal()); exists {
		err = mv.cmp.Matches([]byte(password), digest)
		if err != nil {
			err = errors.Join(bascule.ErrBadCredentials, err)
		}
	} else {
		err = bascule.ErrBadCredentials
	}

	return
}

// NewValidator returns a bascule.Validator that always uses the same hash
// Comparer.  The source S is unused, but conforms to the Validator interface.
func NewValidator[S any](cmp Comparer, creds Credentials) bascule.Validator[S] {
	if cmp == nil {
		cmp = Default()
	}

	return &matcherValidator[S]{
		cmp:   cmp,
		creds: creds,
	}
}
