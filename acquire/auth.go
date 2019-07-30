// Package acquire is used for getting Auths to pass in http requests.
package acquire

import (
	"fmt"
	"net/http"

	"github.com/goph/emperror"
	"github.com/pkg/errors"
)

//ErrMissingAuthValue is returned by an Acquirer when it lacks an auth value
//but it's expected to have one
var ErrMissingAuthValue = errors.New("No authorization value was defined")

// Acquirer gets an Authorization value that can be added to an http request.
// The format of the string returned should be the key, a space, and then the
// auth string: '[AuthType] [AuthValue]'
type Acquirer interface {
	Acquire() (string, error)
}

// DefaultAcquirer is a no-op Acquirer.
type DefaultAcquirer struct{}

//Acquire returns the zero values of the return types
func (d *DefaultAcquirer) Acquire() (string, error) {
	return "", nil
}

//AddAuth adds an auth value to the Authorization header of an http request.
func AddAuth(r *http.Request, acquirer Acquirer) error {
	if r == nil {
		return errors.New("can't add authorization to nil request")
	}

	if acquirer == nil {
		return errors.New("acquirer is undefined")
	}

	auth, err := acquirer.Acquire()

	if err != nil {
		return emperror.Wrap(err, "failed to acquire auth for request")
	}

	if auth != "" {
		r.Header.Set("Authorization", auth)
	}

	return nil
}

type fixedValueAcquirer struct {
	AuthType  string
	AuthValue string
}

func (f *fixedValueAcquirer) Acquire() (string, error) {
	if f.AuthValue == "" {
		return "", ErrMissingAuthValue
	}

	return fmt.Sprintf("%s %s", f.AuthType, f.AuthValue), nil
}
