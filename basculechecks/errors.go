// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

// Reasoner is an error that provides a failure reason to use as a value for a
// metric label.
type Reasoner interface {
	Reason() string
}

type errWithReason struct {
	err    error
	reason string
}

// Error returns the error string.
func (e errWithReason) Error() string {
	return e.err.Error()
}

// Reason returns the reason string for the error.  This is intended to be used
// in a metric label.
func (e errWithReason) Reason() string {
	return e.reason
}

// Unwrap returns the error stored.
func (e errWithReason) Unwrap() error {
	return e.err
}
