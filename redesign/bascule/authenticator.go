package bascule

import "go.uber.org/multierr"

type Authenticator[T Token] interface {
	Authenticate(t T) error
}

type Authenticators[T Token] []Authenticator[T]

func (as Authenticators[T]) Authenticate(t T) (err error) {
	for _, a := range as {
		err = multierr.Append(err, a.Authenticate(t))
	}

	return
}
