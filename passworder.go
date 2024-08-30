// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// Passworder is an optional Token interface that provides access
// to any raw password contained within the token.
type Passworder interface {
	// Password returns the password associated with this Token, if any.
	Password() string
}
