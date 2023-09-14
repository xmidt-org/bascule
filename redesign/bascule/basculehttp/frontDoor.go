package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule/redesign/bascule"
	"go.uber.org/multierr"
)

type FrontDoorOption interface {
	apply(*frontDoor) error
}

type frontDoorOptionFunc func(*frontDoor) error

func (fdof frontDoorOptionFunc) apply(fd *frontDoor) error { return fdof(fd) }

func WithAccessor(a Accessor) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *frontDoor) error {
		fd.accessor = a
		return nil
	})
}

func WithTokenFactory(tf bascule.TokenFactory) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *frontDoor) error {
		fd.tokenFactory = tf
		return nil
	})
}

// FrontDoor is a server middleware that handles the full authentication workflow.
// Authorization is handled separately.
type FrontDoor interface {
	Then(next http.Handler) http.Handler
}

// NewFrontDoor constructs a FrontDoor middleware using the supplied options.
func NewFrontDoor(opts ...FrontDoorOption) (FrontDoor, error) {
	fd := &frontDoor{
		accessor: DefaultAccessor(),
	}

	var err error
	for _, o := range opts {
		err = multierr.Append(err, o.apply(fd))
	}

	if err != nil {
		return nil, err
	}

	return fd, nil
}

type frontDoor struct {
	forbidden func(http.ResponseWriter, *http.Request, error) // TODO

	accessor     Accessor
	tokenFactory bascule.TokenFactory
}

func (fd *frontDoor) handleInvalidCredentials(response http.ResponseWriter, request *http.Request, err error) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusBadRequest)
	response.Write([]byte(err.Error()))
}

func (fd *frontDoor) Then(next http.Handler) http.Handler {
	accessor := fd.accessor
	if accessor == nil {
		accessor = DefaultAccessor()
	}

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		raw, err := accessor.GetCredentials(request)
		if err != nil {
			fd.handleInvalidCredentials(response, request, err)
			return
		}

		token, err := fd.tokenFactory.NewToken(raw)
		if err != nil {
			fd.forbidden(response, request, err)
			return
		}

		request = request.WithContext(
			bascule.WithToken(request.Context(), token),
		)

		next.ServeHTTP(response, request)
	})
}
