// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import "go.uber.org/multierr"

// Authenticator provides a strategy for verifying that a Token
// is valid beyond just simple parsing.  For example, an Authenticator may
// verify certain roles or capabilities.
type Authenticator interface {
	// Authenticate verifies the given Token.
	Authenticate(Token) error
}

// Authenticators is an aggregate Authenticator.
type Authenticators []Authenticator

// Authenticate applies each contained Authenticator in order.  All Authenticators
// are executed.  The returned error, if not nil, will be an aggregate of all errors
// that occurred.
func (as Authenticators) Authenticate(t Token) (err error) {
	for _, auth := range as {
		err = multierr.Append(err, auth.Authenticate(t))
	}

	return
}
