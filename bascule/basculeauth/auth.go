package basculeauth

import (
	"github.com/goph/emperror"
	"github.com/pkg/errors"
	"net/http"
)

type AuthHeaderAcquirer interface {
	Acquire() (string, error)
}

type DefaultAcquirer struct{}

func (d *DefaultAcquirer) Acquire() (string, error) {
	return "", nil
}

func AddAuth(r *http.Request, acquirer AuthHeaderAcquirer) error {
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
