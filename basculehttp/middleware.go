// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
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

// WithTokenParsers appends token parsers to the chain used by the middleware.
// Each invocation of this option is cumulative. Token parsers are run in the
// order supplied via this option.
func WithTokenParsers(tps ...bascule.TokenParser[*http.Request]) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.tokenParsers = m.tokenParsers.Append(tps...)
		return nil
	})
}

// WithAuthentication adds validators used for authentication to this Middleware.  Each
// invocation of this option is cumulative.  Authentication validators are run in the order
// supplied by this option.
func WithAuthentication(v ...bascule.Validator[*http.Request]) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.authentication = m.authentication.Append(v...)
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

// WithAuthorization adds authorizers to this Middleware.  Each invocation of this option
// is cumulative.  Authorizers are executed for each request in the order supplied
// via this option.
//
// A Middleware requires all its options to pass in order to allow access.  Callers can
// use Authorizers.Any to create authorizers that require only (1) authorizer to pass.
// This is useful for use cases like admin access or alternate capabilities.
func WithAuthorization(a ...bascule.Authorizer[*http.Request]) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.authorization = m.authorization.Append(a...)
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
	tokenParsers   bascule.TokenParsers[*http.Request]
	authentication bascule.Validators[*http.Request]
	authorization  bascule.Authorizers[*http.Request]
	challenges     Challenges

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

func (m *Middleware) parseToken(ctx context.Context, request *http.Request) (bascule.Token, error) {
	return m.tokenParsers.Parse(ctx, request)
}

func (m *Middleware) authenticate(ctx context.Context, request *http.Request, token bascule.Token) (bascule.Token, error) {
	return m.authentication.Validate(ctx, request, token)
}

func (m *Middleware) authorize(ctx context.Context, token bascule.Token, request *http.Request) error {
	return m.authorization.Authorize(ctx, request, token)
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
	token, err := fd.parseToken(ctx, request)
	if err != nil {
		// by default, failing to parse a token is a malformed request
		fd.writeError(response, request, http.StatusBadRequest, err)
		return
	}

	token, err = fd.authenticate(ctx, request, token)
	if err != nil {
		// at this point in the workflow, the request has valid credentials.  we use
		// StatusForbidden as the default because any failure to authenticate isn't a
		// case where the caller needs to supply credentials.  Rather, the supplied
		// credentials aren't adequate enough.
		fd.writeError(response, request, http.StatusForbidden, err)
		return
	}

	ctx = bascule.WithToken(ctx, token)
	err = fd.authorize(ctx, token, request)
	if err != nil {
		fd.writeError(response, request, http.StatusForbidden, err)
		return
	}

	fd.protected.ServeHTTP(response, request.WithContext(ctx))
}
