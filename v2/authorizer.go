// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// Authorizer is a strategy for verifying that a given Token has
// access to resources.
type Authorizer interface {
	// Authorize verifies that the given Token can access a resource.
	Authorize(resource any, t Token) error
}
