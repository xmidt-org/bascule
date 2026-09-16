// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import "errors"

// The errors Approve returns.  Each is joined with bascule.ErrUnauthorized, so
// a caller that only cares whether the request was authorized is unaffected.
var (
	// ErrNoCapabilities indicates the token carried no capabilities at all, and
	// so could never have been authorized by this approver.  A token that has
	// no notion of capabilities, such as basic auth, produces this as well.
	ErrNoCapabilities = errors.New("no capabilities")

	// ErrNoMatchingCapability indicates the token had capabilities, but none of
	// them authorized this request.
	ErrNoMatchingCapability = errors.New("no matching capability")
)
