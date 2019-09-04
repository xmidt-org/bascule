package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/xmidt-org/bascule/bascule"
	"github.com/go-kit/kit/log/level"
)

const (
	DefaultHeaderName = "Authorization"
)

type constructor struct {
	headerName      string
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

		i := strings.IndexByte(authorization, ' ')
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
		token, err := tf.ParseAndValidate(ctx, request, key, authorization[i+1:])
		if err != nil {
			c.error(logger, ParseFailed, authorization, err)
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
	logger.Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, err.Error(), "auth", auth)
	c.onErrorResponse(e, err)
}

type COption func(*constructor)

func WithHeaderName(headerName string) COption {
	return func(c *constructor) {
		if len(headerName) > 0 {
			c.headerName = headerName
		} else {
			c.headerName = DefaultHeaderName
		}
	}
}

func WithTokenFactory(key bascule.Authorization, tf TokenFactory) COption {
	return func(c *constructor) {
		c.authorizations[key] = tf
	}
}

func WithCLogger(getLogger func(context.Context) bascule.Logger) COption {
	return func(c *constructor) {
		c.getLogger = getLogger
	}
}

func WithCErrorResponseFunc(f OnErrorResponse) COption {
	return func(c *constructor) {
		c.onErrorResponse = f
	}
}

// New returns an Alice-style constructor which decorates HTTP handlers with security code
func NewConstructor(options ...COption) func(http.Handler) http.Handler {
	c := &constructor{
		headerName:      DefaultHeaderName,
		authorizations:  make(map[bascule.Authorization]TokenFactory),
		getLogger:       bascule.GetDefaultLoggerFunc,
		onErrorResponse: DefaultOnErrorResponse,
	}

	for _, o := range options {
		o(c)
	}

	return c.decorate
}
