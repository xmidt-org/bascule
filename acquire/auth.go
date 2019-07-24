// package acquire is used for getting Auths to pass in http requests.
package acquire

import (
	"net/http"

	"github.com/goph/emperror"
	"github.com/pkg/errors"
)

// Acquirer gets an Authorization value that can be added to an http request.
// The format of the string returned should be the key, a space, and then the
// auth string.
type Acquirer interface {
	Acquire() (string, error)
}

// DefaultAcquirer returns nothing.  This would not be a valid Authorization.
type DefaultAcquirer struct{}

func (d *DefaultAcquirer) Acquire() (string, error) {
	return "", nil
}

// AddAuth adds an auth value to the Authorization header of an http request.
func AddAuth(r *http.Request, acquirer Acquirer) error {
	if r == nil {
		return errors.New("can't add authorization to nil request")
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

//TODO: create a const value acquirer?
type fixedValueAcquirer struct {
	Auth string
}

func (f *fixedValueAcquirer) Acquire() (string, error) {
	return f.Auth, nil
}
