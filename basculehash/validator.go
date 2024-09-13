// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"

	"github.com/xmidt-org/bascule"
)

// Matcher is the common interface between a Principals and a Store.
type Matcher interface {
	// Matches checks the associated digest with the given plaintext.
	Matches(Comparer, string, []byte) (bool, error)
}

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

	matched, matchErr := mv.m.Matches(mv.cmp, t.Principal(), []byte(password))
	switch {
	case !matched:
		err = bascule.ErrBadCredentials

	case matchErr != nil:
		err = bascule.ErrBadCredentials
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
