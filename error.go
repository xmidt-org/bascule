/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package bascule

import (
	"fmt"
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
	errors := make([]string, len(e))
	for _, err := range e {
		errors = append(errors, err.Error())
	}
	return fmt.Sprintf("multiple errors: [%v]", strings.Join(errors, ", "))
}

// Errors returns the list of errors.
func (e Errors) Errors() []error {
	return e
}
