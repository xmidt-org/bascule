// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"strconv"

	"github.com/xmidt-org/bascule/v1"
	"go.uber.org/multierr"
)

// MiddlewareOption is a functional option for tailoring a Middleware.
type MiddlewareOption interface {
	apply(*Middleware) error
}

type middlewareOptionFunc func(*Middleware) error

func (mof middlewareOptionFunc) apply(m *Middleware) error {
	return mof(m)
}

// WithAuthenticator supplies the Authenticator workflow for the middleware.
//
// If no authenticator is supplied, NewMiddeware returns an error.
func WithAuthenticator(authenticator *bascule.Authenticator[*http.Request]) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.authenticator = authenticator
		return nil
	})
}

// WithAuthorizer supplies the Authorizer workflow for the middleware.
//
// The Authorizer is optional.  If no authorizer is supplied, then no authorization
// takes place and no authorization events are fired.
func WithAuthorizer(authorizer *bascule.Authorizer[*http.Request]) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.authorizer = authorizer
		return nil
	})
}

// WithChallenges adds WWW-Authenticate challenges to be used when a StatusUnauthorized is
// detected.  Multiple invocations of this option are cumulative.  Each challenge results
// in a separate WWW-Authenticate header, in the order specified by this option.
func WithChallenges(ch ...Challenge) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.challenges.Add(ch...)
		return nil
	})
}

// WithErrorStatusCoder sets the strategy used to write errors to HTTP responses.  If this
// option is omitted or if esc is nil, DefaultErrorStatusCoder is used.
func WithErrorStatusCoder(esc ErrorStatusCoder) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		if esc != nil {
			m.errorStatusCoder = esc
		} else {
			m.errorStatusCoder = DefaultErrorStatusCoder
		}

		return nil
	})
}

// WithErrorMarshaler sets the strategy used to marshal errors to HTTP response bodies.  If this
// option is omitted or if esc is nil, DefaultErrorMarshaler is used.
func WithErrorMarshaler(em ErrorMarshaler) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		if em != nil {
			m.errorMarshaler = em
		} else {
			m.errorMarshaler = DefaultErrorMarshaler
		}

		return nil
	})
}

// Middleware is an immutable configuration that can decorate multiple handlers.
type Middleware struct {
	authenticator *bascule.Authenticator[*http.Request]
	authorizer    *bascule.Authorizer[*http.Request]
	challenges    Challenges

	errorStatusCoder ErrorStatusCoder
	errorMarshaler   ErrorMarshaler
}

// NewMiddleware creates an immutable Middleware instance from a supplied set of options.
// No options will result in a Middleware with default behavior.
func NewMiddleware(opts ...MiddlewareOption) (m *Middleware, err error) {
	m = &Middleware{
		errorStatusCoder: DefaultErrorStatusCoder,
		errorMarshaler:   DefaultErrorMarshaler,
	}

	for _, o := range opts {
		err = multierr.Append(err, o.apply(m))
	}

	return
}

// Then produces an http.Handler that uses this Middleware's workflow to protected
// a given handler.
func (m *Middleware) Then(protected http.Handler) http.Handler {
	if protected == nil {
		protected = http.DefaultServeMux
	}

	return &frontDoor{
		Middleware: m,
		protected:  protected,
	}
}

// ThenFunc is like Then, but protects a handler function.
func (m *Middleware) ThenFunc(protected http.HandlerFunc) http.Handler {
	if protected == nil {
		return m.Then(nil)
	}

	return m.Then(protected)
}

// writeError handles writing error information to an HTTP response.  This will include any WWW-Authenticate
// challenges that are configured if a 401 status is detected.
//
// The defaultCode is used as the response status code if the given error does not supply a StatusCode method.
//
// If the error supports JSON or text marshaling, that is used for the response body.  Otherwise, a text/plain
// response with the Error() method's text is used.
func (m *Middleware) writeError(response http.ResponseWriter, request *http.Request, defaultCode int, err error) {
	statusCode := m.errorStatusCoder(request, err)
	if statusCode < 100 {
		statusCode = defaultCode
	}

	if statusCode == http.StatusUnauthorized {
		m.challenges.WriteHeader(response.Header())
	}

	contentType, content, marshalErr := m.errorMarshaler(request, err)

	// TODO: what if marshalErr != nil ?
	if marshalErr == nil {
		response.Header().Set("Content-Type", contentType)
		response.Header().Set("Content-Length", strconv.Itoa(len(content)))
		response.WriteHeader(statusCode)
		response.Write(content) // TODO: handle errors here somehow
	}
}

// frontDoor is the internal handler implementation that protects a handler
// using the bascule workflow.
type frontDoor struct {
	*Middleware
	protected http.Handler
}

// ServeHTTP implements the bascule workflow, using the configured middleware.
func (fd *frontDoor) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	token, err := fd.authenticator.Authenticate(ctx, request)
	if err != nil {
		// by default, failing to parse a token is a malformed request
		fd.writeError(response, request, http.StatusBadRequest, err)
		return
	}

	ctx = bascule.WithToken(ctx, token)

	// the authorizer is optional
	if fd.authorizer != nil {
		err = fd.authorizer.Authorize(ctx, request, token)
		if err != nil {
			fd.writeError(response, request, http.StatusForbidden, err)
			return
		}
	}

	fd.protected.ServeHTTP(response, request.WithContext(ctx))
}
