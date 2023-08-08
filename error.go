// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"strings"
)

// Error is an optional interface to be implemented by security related errors
type Error interface {
	Cause() error
	Reason() string
}

// MultiError is an interface that provides a list of errors.
type MultiError interface {
	Errors() []error
}

// Errors is a Multierror that also acts as an error, so that a log-friendly
// string can be returned but each error in the list can also be accessed.
type Errors []error

// Error concatenates the list of error strings to provide a single string
// that can be used to represent the errors that occurred.
func (e Errors) Error() string {
	var output strings.Builder
	output.Write([]byte("multiple errors: ["))
	for i, msg := range e {
		if i > 0 {
			output.WriteRune(',')
			output.WriteRune(' ')
		}

		output.WriteString(msg.Error())
	}
	output.WriteRune(']')

	return output.String()
}

// Errors returns the list of errors.
func (e Errors) Errors() []error {
	return e
}
