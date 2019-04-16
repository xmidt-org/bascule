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

type MultiError interface {
	Errors() []error
}

type Errors []error

func (e Errors) Error() string {
	var errors []string
	for _, err := range e {
		errors = append(errors, err.Error())
	}
	return fmt.Sprintf("multiple errors: [%v]", strings.Join(errors, ", "))
}

func (e Errors) Errors() []error {
	return e
}
