package bascule

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
	return "multiple errors"
}

func (e Errors) Errors() []error {
	return e
}
