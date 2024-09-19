// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"
	"errors"

	"github.com/xmidt-org/bascule"
)

type matcherValidator[S any] struct {
	cmp Comparer
	m   Matcher
}

func (mv *matcherValidator[S]) Validate(ctx context.Context, _ S, t bascule.Token) (next bascule.Token, err error) {
	next = t
	password, ok := bascule.GetPassword(t)
	if !ok {
		return
	}

	if err = mv.m.Matches(mv.cmp, t.Principal(), []byte(password)); err != nil {
		err = errors.Join(bascule.ErrBadCredentials, err)
	}

	return
}

// NewValidator returns a bascule.Validator that always uses the same hash
// Comparer.  The source S is unused, but conforms to the Validator interface.
func NewValidator[S any](cmp Comparer, m Matcher) bascule.Validator[S] {
	v := &matcherValidator[S]{
		cmp: cmp,
		m:   m,
	}

	if v.cmp == nil {
		v.cmp = Default()
	}

	return v
}
