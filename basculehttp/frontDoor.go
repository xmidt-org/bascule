package basculehttp

import (
	"encoding"
	"encoding/json"
	"net/http"

	"github.com/xmidt-org/bascule/v1"
	"go.uber.org/multierr"
)

// FrontDoorOption is a functional option for tailoring a FrontDoor.
type FrontDoorOption interface {
	apply(*FrontDoor) error
}

type frontDoorOptionFunc func(*FrontDoor) error

func (fdof frontDoorOptionFunc) apply(fd *FrontDoor) error {
	return fdof(fd)
}

// WithProtected sets the HTTP handler that is to be protected by the front door.
// If this option is omitted, http.DefaultServeMux is used.
func WithProtected(h http.Handler) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *FrontDoor) error {
		fd.protected = h
		return nil
	})
}

// WithAccessor defines how the front door will obtain the raw credentials from
// HTTP requests.  If this option is omitted, DefaultAccessor() is used.
func WithAccessor(a Accessor) FrontDoorOption {
	return frontDoorOptionFunc(func(fd *FrontDoor) error {
		fd.accessor = a
		return nil
	})
}

// FrontDoor implements the bascule HTTP workflow.  This type is an http.Handler
// that protects a given handler using bascule's authentication and authorization
// workflows.
type FrontDoor struct {
	protected         http.Handler
	accessor          Accessor
	credentialsParser bascule.CredentialsParser
	tokenParsers      bascule.TokenParsers
	authentication    bascule.Validators
}

func NewFrontDoor(opts ...FrontDoorOption) (fd *FrontDoor, err error) {
	fd = &FrontDoor{
		protected:         http.DefaultServeMux,
		accessor:          DefaultAccessor(),
		credentialsParser: DefaultCredentialsParser(),
		tokenParsers:      DefaultTokenParsers(),
	}

	for _, o := range opts {
		err = multierr.Append(err, o.apply(fd))
	}

	return
}

func (fd *FrontDoor) writeError(response http.ResponseWriter, defaultCode int, err error) {
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

func (fd *FrontDoor) ServeHTTP(response http.ResponseWriter, request *http.Request) {
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
