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
	var errors []string
	for _, err := range e {
		errors = append(errors, err.Error())
	}
	return fmt.Sprintf("multiple errors: [%v]", strings.Join(errors, ", "))
}

// Errors returns the list of errors.
func (e Errors) Errors() []error {
	return e
}
