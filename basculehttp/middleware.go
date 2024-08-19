// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/xmidt-org/bascule/v1"
	"go.uber.org/multierr"
)

var (
	// ErrNoAuthenticator is returned by NewMiddleware to indicate that an Authorizer
	// was configured without an Authenticator.
	ErrNoAuthenticator = errors.New("An Authenticator is required if an Authorizer is configured")
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
func WithAuthenticator(authenticator *bascule.Authenticator[*http.Request]) MiddlewareOption {
	return UseAuthenticator(authenticator, nil)
}

// UseAuthenticator is a variant of WithAuthenticator that allows a caller to
// nest function calls a little easier.  The output of NewAuthenticator
// can be passed directly to this option.
//
// Note: If no authenticator is supplied, NewMiddeware returns an error.
func UseAuthenticator(authenticator *bascule.Authenticator[*http.Request], err error) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		if err != nil {
			return err
		}

		m.authenticator = authenticator
		return nil
	})
}

// WithAuthorizer supplies the Authorizer workflow for the middleware.
//
// The Authorizer is optional.  If no authorizer is supplied, then no authorization
// takes place and no authorization events are fired.
func WithAuthorizer(authorizer *bascule.Authorizer[*http.Request]) MiddlewareOption {
	return UseAuthorizer(authorizer, nil)
}

// UseAuthorizer is a variant of WithAuthorizer that allows a caller to
// nest function calls a little easier.  The output of NewAuthorizer
// can be passed directly to this option.
func UseAuthorizer(authorizer *bascule.Authorizer[*http.Request], err error) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		if err != nil {
			return err
		}

		m.authorizer = authorizer
		return nil
	})
}

// WithChallenges adds WWW-Authenticate challenges to be used when a StatusUnauthorized is
// detected.  Multiple invocations of this option are cumulative.  Each challenge results
// in a separate WWW-Authenticate header, in the order specified by this option.
func WithChallenges(ch ...Challenge) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.challenges = m.challenges.Append(ch...)
		return nil
	})
}

// WithErrorStatusCoder sets the strategy used to write errors to HTTP responses.  If this
// option is omitted or if esc is nil, DefaultErrorStatusCoder is used.
func WithErrorStatusCoder(esc ErrorStatusCoder) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.errorStatusCoder = esc
		return nil
	})
}

// WithErrorMarshaler sets the strategy used to marshal errors to HTTP response bodies.  If this
// option is omitted or if esc is nil, DefaultErrorMarshaler is used.
func WithErrorMarshaler(em ErrorMarshaler) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.errorMarshaler = em
		return nil
	})
}

// Middleware is an immutable HTTP workflow that can decorate multiple handlers.
//
// A Middleware can have either or both of an Authenticator, which creates
// tokens from HTTP requests, and an Authorizer, which approves access to
// the resource identified by the request.  The behavior of a Middleware
// depends mostly on these two components.
//
// If both an authenticator and an authorizer are supplied, the full bascule
// workflow, including events, is implemented.
//
// If an authenticator is supplied without an authorizer, only token creation
// is implemented.  Without an authorizer, it is assumed that all tokens have
// access to all requests.
//
// If no authenticator is supplied, but an authorizer IS supplied, then
// NewMiddleware returns an error.  An authenticator is required in order to
// create tokens.
//
// Finally, if neither an authenticator or an authorizer is supplied,
// then this Middleware is a noop.  Any attempt to decorate handlers will
// result in those handlers being returned as is.  This allows a Middleware
// to be turned off via configuration.
type Middleware struct {
	authenticator *bascule.Authenticator[*http.Request]
	authorizer    *bascule.Authorizer[*http.Request]
	challenges    Challenges

	errorStatusCoder ErrorStatusCoder
	errorMarshaler   ErrorMarshaler
}

// NewMiddleware creates an immutable Middleware instance from a supplied set of options.
// No options will result in a Middleware with default behavior.
//
// If no authenticator is configured, but an authorizer is, this function returns
// ErrNoAuthenticator.
//
// Note that if no workflow components are configured, i.e. neither an authenticator nor
// an authorizer are supplied, then the returned Middleware is a noop.
func NewMiddleware(opts ...MiddlewareOption) (m *Middleware, err error) {
	m = new(Middleware)
	for _, o := range opts {
		err = multierr.Append(err, o.apply(m))
	}

	switch {
	case err != nil:
		m = nil

	case m.authenticator == nil && m.authorizer != nil:
		err = multierr.Append(err, ErrNoAuthenticator)
		m = nil

	default:
		// cleanup after the options run
		if m.errorStatusCoder == nil {
			m.errorStatusCoder = DefaultErrorStatusCoder
		}

		if m.errorMarshaler == nil {
			m.errorMarshaler = DefaultErrorMarshaler
		}
	}

	return
}

// Then produces an http.Handler that uses this Middleware's workflow to protected
// a given handler.
func (m *Middleware) Then(protected http.Handler) http.Handler {
	if protected == nil {
		protected = http.DefaultServeMux
	}

	// no point in decorating if there's no workflow
	// this also allows a Middleware to be turned off via configuration
	if m.authenticator == nil && m.authorizer == nil {
		return protected
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

// writeRawError is a fallback to write an error that came from this package.
// The response is always a text/plain representation of the error.
func (m *Middleware) writeRawError(response http.ResponseWriter, err error) {
	response.WriteHeader(http.StatusInternalServerError)
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")

	errBody := []byte(err.Error())
	response.Header().Set("Content-Length", strconv.Itoa(len(errBody)))
	response.Write(errBody)
}

// writeWorkflowError handles writing an error that came from the bascule workflow to an HTTP request.
// This will include writing any HTTP challenges if a 401 status is detected.
//
// The defaultCode is used as the response status code if the given error does not supply a StatusCode method.
//
// If the error supports JSON or text marshaling, that is used for the response body.  Otherwise, a text/plain
// response with the Error() method's text is used.
func (m *Middleware) writeWorkflowError(response http.ResponseWriter, request *http.Request, defaultCode int, err error) {
	statusCode := m.errorStatusCoder(request, err)
	if statusCode < 100 {
		statusCode = defaultCode
	}

	var (
		contentType string
		content     []byte
		writeErr    error
	)

	if statusCode == http.StatusUnauthorized {
		writeErr = m.challenges.WriteHeader("", response.Header())
	}

	if writeErr == nil {
		contentType, content, writeErr = m.errorMarshaler(request, err)
	}

	if writeErr != nil {
		m.writeRawError(response, writeErr)
	} else {
		response.Header().Set("Content-Type", contentType)
		response.Header().Set("Content-Length", strconv.Itoa(len(content)))
		response.WriteHeader(statusCode)
		response.Write(content)
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

	// an authenticator is is required if we are decorating
	// if the authenticator was nil, a frontDoor won't get created
	token, err := fd.authenticator.Authenticate(ctx, request)
	if err != nil {
		// by default, failing to parse a token is a malformed request
		fd.writeWorkflowError(response, request, http.StatusBadRequest, err)
		return
	}

	ctx = bascule.WithToken(ctx, token)

	// the authorizer is optional
	if fd.authorizer != nil {
		err = fd.authorizer.Authorize(ctx, request, token)
		if err != nil {
			fd.writeWorkflowError(response, request, http.StatusForbidden, err)
			return
		}
	}

	fd.protected.ServeHTTP(response, request.WithContext(ctx))
}
