// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"encoding"
	"encoding/json"
	"net/http"

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

// WithAccessor configures a credentials Accessor for this Middleware.  If not supplied
// or if the supplied Accessor is nil, DefaultAccessor() is used.
func WithAccessor(a Accessor) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		if a != nil {
			m.accessor = a
		} else {
			m.accessor = DefaultAccessor()
		}

		return nil
	})
}

// WithCredentialsParser configures a credentials parser for this Middleware.  If not supplied
// or if the supplied CredentialsParser is nil, DefaultCredentialsParser() is used.
func WithCredentialsParser(cp bascule.CredentialsParser) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		if cp != nil {
			m.credentialsParser = cp
		} else {
			m.credentialsParser = DefaultCredentialsParser()
		}

		return nil
	})
}

// WithTokenParser registers a token parser for the given scheme.  If the scheme has
// already been registered, the given parser will replace that registration.
//
// The parser cannot be nil.
func WithTokenParser(scheme bascule.Scheme, tp bascule.TokenParser) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.tokenParsers.Register(scheme, tp)
		return nil
	})
}

// WithAuthentication adds validators used for authentication to this Middleware.  Each
// invocation of this option is cumulative.  Authentication validators are run in the order
// supplied by this option.
func WithAuthentication(v ...bascule.Validator) MiddlewareOption {
	return middlewareOptionFunc(func(m *Middleware) error {
		m.authentication.Add(v...)
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

// Middleware is an immutable configuration that can decorate multiple handlers.
type Middleware struct {
	accessor          Accessor
	credentialsParser bascule.CredentialsParser
	tokenParsers      bascule.TokenParsers
	authentication    bascule.Validators
	challenges        Challenges
}

func NewMiddleware(opts ...MiddlewareOption) (m *Middleware, err error) {
	m = &Middleware{
		accessor:          DefaultAccessor(),
		credentialsParser: DefaultCredentialsParser(),
		tokenParsers:      DefaultTokenParsers(),
	}

	for _, o := range opts {
		err = multierr.Append(err, o.apply(m))
	}

	return
}

func (m *Middleware) Then(protected http.Handler) http.Handler {
	if protected == nil {
		protected = http.DefaultServeMux
	}

	return &frontDoor{
		middleware: m,
		protected:  protected,
	}
}

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
func (m *Middleware) writeError(response http.ResponseWriter, defaultCode int, err error) {
	var (
		statusCode  = defaultCode
		content     []byte
		contentType string
		marshalErr  error
	)

	type statusCoder interface {
		StatusCode() int
	}

	if sc, ok := err.(statusCoder); ok {
		statusCode = sc.StatusCode()
	}

	switch m := err.(type) {
	case json.Marshaler:
		content, marshalErr = m.MarshalJSON()
		contentType = "application/json"

	case encoding.TextMarshaler:
		content, marshalErr = m.MarshalText()
		contentType = "text/plain; charset=utf-8"
	}

	if len(content) == 0 || marshalErr != nil {
		// fallback to simply writing the error text
		content = []byte(err.Error())
		contentType = "text/plain; charset=utf-8"
	}

	response.Header().Set("Content-Type", contentType)
	if statusCode == http.StatusUnauthorized {
		m.challenges.WriteHeader(response.Header())
	}

	response.WriteHeader(statusCode)
	response.Write(content) // TODO: handle errors here somehow
}

func (m *Middleware) getCredentialsAndToken(ctx context.Context, request *http.Request) (c bascule.Credentials, t bascule.Token, err error) {
	var raw string
	raw, err = m.accessor.GetCredentials(request)
	if err == nil {
		c, err = m.credentialsParser.Parse(raw)
	}

	if err == nil {
		t, err = m.tokenParsers.Parse(ctx, c)
	}

	return
}

func (m *Middleware) authenticate(ctx context.Context, token bascule.Token) error {
	return m.authentication.Validate(ctx, token)
}

// frontDoor is the internal handler implementation that protects a handler
// using the bascule workflow.
type frontDoor struct {
	middleware *Middleware
	protected  http.Handler
}

func (fd *frontDoor) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	creds, token, err := fd.middleware.getCredentialsAndToken(ctx, request)
	if err != nil {
		// by default, failing to parse a token is a malformed request
		fd.middleware.writeError(response, http.StatusBadRequest, err)
		return
	}

	ctx = bascule.WithCredentials(ctx, creds)
	err = fd.middleware.authenticate(ctx, token)
	if err == nil {
		fd.middleware.writeError(response, http.StatusUnauthorized, err)
		return
	}

	ctx = bascule.WithToken(ctx, token)
	fd.protected.ServeHTTP(response, request.WithContext(ctx))
}
