// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"errors"
	"net/http"

	"github.com/xmidt-org/bascule/v2"
	"go.uber.org/multierr"
)

type FrontDoorOption interface {
	apply(*frontDoor) error
}

type frontDoorOptionFunc func(*frontDoor) error

func (fdof frontDoorOptionFunc) apply(fd *frontDoor) error { return fdof(fd) }

// WithAccessor associates a strategy for extracting the raw, serialized token
// from a request.  If this option is not supplied, DefaultAccessor() is used.
func WithAccessor(a Accessor) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *frontDoor) error {
		fd.accessor = a
		return nil
	})
}

// WithTokenFactory associates the given token factory with a front door.
func WithTokenFactory(tf bascule.TokenFactory) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *frontDoor) error {
		fd.tokenFactory = tf
		return nil
	})
}

// WithChallenges describes challenges to be issued when no credentials
// are supplied.  If no challenges are associated with a FrontDoor, then
// http.StatusForbidden is returned whenever credentials are not found in
// the request.  Otherwise, http.StatusUnauthorized is returned along
// with a WWW-Authenticate header for each challenge.
func WithChallenges(c ...Challenge) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *frontDoor) error {
		fd.challenges = append(fd.challenges, c...)
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
	challenges Challenges
	forbidden  func(http.ResponseWriter, *http.Request, error) // TODO

	accessor     Accessor
	tokenFactory bascule.TokenFactory
}

func (fd *frontDoor) handleMissingCredentials(response http.ResponseWriter, err *bascule.MissingCredentialsError) {
	var statusCode = http.StatusForbidden
	if fd.challenges.WriteHeader(response.Header()) > 0 {
		statusCode = http.StatusUnauthorized
	}

	response.WriteHeader(statusCode)
}

func (fd *frontDoor) handleInvalidCredentials(response http.ResponseWriter, err *bascule.InvalidCredentialsError) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusUnauthorized)
	response.Write([]byte(err.Error()))
}

func (fd *frontDoor) handleError(response http.ResponseWriter, request *http.Request, err error) {
	{
		var missing *bascule.MissingCredentialsError
		if errors.As(err, &missing) {
			fd.handleMissingCredentials(response, missing)
			return
		}
	}

	{
		var invalid *bascule.InvalidCredentialsError
		if errors.As(err, &invalid) {
			fd.handleInvalidCredentials(response, invalid)
			return
		}
	}
}

func (fd *frontDoor) Then(next http.Handler) http.Handler {
	accessor := fd.accessor
	if accessor == nil {
		accessor = DefaultAccessor()
	}

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var token bascule.Token
		raw, err := accessor.GetCredentials(request)
		if err == nil {
			token, err = fd.tokenFactory.NewToken(raw)
		}

		if err != nil {
			fd.handleError(response, request, err)
			return
		}

		request = request.WithContext(
			bascule.WithToken(request.Context(), token),
		)

		next.ServeHTTP(response, request)
	})
}
