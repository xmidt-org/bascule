package basculehttp

import (
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

// Middleware is an immutable configuration that can decorate multiple handlers.
type Middleware struct {
	accessor          Accessor
	credentialsParser bascule.CredentialsParser
	tokenParsers      bascule.TokenParsers
	authentication    bascule.Validators
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

func (m *Middleware) clone() (clone Middleware) {
	clone = *m
	clone.tokenParsers = clone.tokenParsers.Clone()
	return
}

func (m *Middleware) Then(protected http.Handler) http.Handler {
	if protected == nil {
		protected = http.DefaultServeMux
	}

	return &frontDoor{
		Middleware: m.clone(),
		protected:  protected,
	}
}

func (m *Middleware) ThenFunc(protected http.HandlerFunc) http.Handler {
	if protected == nil {
		return m.Then(nil)
	}

	return m.Then(protected)
}

type frontDoor struct {
	Middleware
	protected http.Handler
}

func (fd *frontDoor) writeError(response http.ResponseWriter, defaultCode int, err error) {
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
	response.WriteHeader(statusCode)
	response.Write(content) // TODO: handle errors here somehow
}

func (fd *frontDoor) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	var (
		ctx      = request.Context()
		creds    bascule.Credentials
		token    bascule.Token
		raw, err = fd.accessor.GetCredentials(request)
	)

	if err == nil {
		creds, err = fd.credentialsParser.Parse(raw)
	}

	if err == nil {
		token, err = fd.tokenParsers.Parse(ctx, creds)
	}

	if err != nil {
		fd.writeError(response, http.StatusBadRequest, err)
		return
	}

	err = fd.authentication.Validate(ctx, token)
	if err != nil {
		fd.writeError(response, http.StatusUnauthorized, err)
		return
	}

	ctx = bascule.WithCredentials(ctx, creds)
	ctx = bascule.WithToken(ctx, token)
	fd.protected.ServeHTTP(response, request.WithContext(ctx))
}
