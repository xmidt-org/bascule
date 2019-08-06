// Package acquire is used for getting Auths to pass in http requests.
package acquire

import (
	"net/http"

	"github.com/goph/emperror"
	"github.com/pkg/errors"
)

//ErrEmptyCredentials is returned whenever an Acquirer is attempted to
//be built with empty credentials
//Use DefaultAcquirer for such no-op use case
var ErrEmptyCredentials = errors.New("Empty credentials are not valid")

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
	AuthValue string
}

func (f *fixedValueAcquirer) Acquire() (string, error) {
	return f.AuthValue, nil
}

//NewFixedAuthAcquirer returns an acquirer with a fixed authentication
//value. 'authValue' should be the full authorization value of the form '[type] [token]'
//(i.e. Bearer xyz)
func NewFixedAuthAcquirer(authValue string) (Acquirer, error) {
	if authValue != "" {
		return &fixedValueAcquirer{
			AuthValue: authValue}, nil
	}
	return nil, ErrEmptyCredentials
}
