package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/goph/emperror"
	"github.com/xmidt-org/bascule"
)

const (
	// DefaultHeaderName is the http header to get the authorization
	// information from.
	DefaultHeaderName = "Authorization"

	// DefaultHeaderDelimiter is the character between the authorization and
	// its key.
	DefaultHeaderDelimiter = " "
)

type constructor struct {
	headerName      string
	headerDelimiter string
	authorizations  map[bascule.Authorization]TokenFactory
	getLogger       func(context.Context) bascule.Logger
	onErrorResponse OnErrorResponse
}

func (c *constructor) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		logger := c.getLogger(request.Context())
		if logger == nil {
			logger = bascule.GetDefaultLoggerFunc(request.Context())
		}
		authorization := request.Header.Get(c.headerName)
		if len(authorization) == 0 {
			err := errors.New("no authorization header")
			c.error(logger, MissingHeader, "", err)
			response.WriteHeader(http.StatusForbidden)
			return
		}

		i := strings.Index(authorization, c.headerDelimiter)
		if i < 1 {
			err := errors.New("unexpected authorization header value")
			c.error(logger, InvalidHeader, authorization, err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}

		key := bascule.Authorization(
			textproto.CanonicalMIMEHeaderKey(authorization[:i]),
		)

		tf, supported := c.authorizations[key]
		if !supported {
			err := fmt.Errorf("key not supported: [%v]", key)
			c.error(logger, KeyNotSupported, authorization, err)
			response.WriteHeader(http.StatusForbidden)
			return
		}

		ctx := request.Context()
		token, err := tf.ParseAndValidate(ctx, request, key, authorization[i+len(c.headerDelimiter):])
		if err != nil {
			c.error(logger, ParseFailed, authorization, emperror.Wrap(err, "failed to parse and validate token"))
			WriteResponse(response, http.StatusForbidden, err)
			return
		}

		ctx = bascule.WithAuthentication(
			request.Context(),
			bascule.Authentication{
				Authorization: key,
				Token:         token,
				Request: bascule.Request{
					URL:    request.URL.EscapedPath(),
					Method: request.Method,
				},
			},
		)
		logger.Log(level.Key(), level.DebugValue(), "msg", "authentication added to context",
			"token", token, "key", key)

		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func (c *constructor) error(logger bascule.Logger, e ErrorResponseReason, auth string, err error) {
	log.With(logger, emperror.Context(err)...).Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, err.Error(), "auth", auth)
	c.onErrorResponse(e, err)
}

// COption is any function that modifies the constructor - used to configure
// the constructor.
type COption func(*constructor)

// WithHeaderName sets the headername and verifies it's valid.  The headername
// is the name of the header to get the authorization information from.
func WithHeaderName(headerName string) COption {
	return func(c *constructor) {
		if len(headerName) > 0 {
			c.headerName = headerName
		}
	}
}

func WithHeaderDelimiter(delimiter string) COption {
	return func(c *constructor) {
		if len(delimiter) > 0 {
			c.headerDelimiter = delimiter
		}
	}
}

// WithTokenFactory sets the TokenFactory for the constructor to use.
func WithTokenFactory(key bascule.Authorization, tf TokenFactory) COption {
	return func(c *constructor) {
		c.authorizations[key] = tf
	}
}

// WithCLogger sets the function to use to get the logger from the context.
// If no logger is set, nothing is logged.
func WithCLogger(getLogger func(context.Context) bascule.Logger) COption {
	return func(c *constructor) {
		c.getLogger = getLogger
	}
}

// WithCErrorResponseFunc sets the function that is called when an error occurs.
func WithCErrorResponseFunc(f OnErrorResponse) COption {
	return func(c *constructor) {
		c.onErrorResponse = f
	}
}

// NewConstructor creates an Alice-style decorator function that acts as
// middleware: parsing the http request to get a Token, which is added to the
// context.
func NewConstructor(options ...COption) func(http.Handler) http.Handler {
	c := &constructor{
		headerName:      DefaultHeaderName,
		headerDelimiter: DefaultHeaderDelimiter,
		authorizations:  make(map[bascule.Authorization]TokenFactory),
		getLogger:       bascule.GetDefaultLoggerFunc,
		onErrorResponse: DefaultOnErrorResponse,
	}

	for _, o := range options {
		o(c)
	}

	return c.decorate
}
