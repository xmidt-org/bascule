package basculehttp

import (
	"context"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/Comcast/comcast-bascule/bascule"
	"github.com/go-kit/kit/log/level"
)

const (
	DefaultHeaderName = "Authorization"
)

type constructor struct {
	headerName     string
	authorizations map[bascule.Authorization]TokenFactory
	getLogger      func(context.Context) bascule.Logger
}

func (c *constructor) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		logger := c.getLogger(request.Context())
		authorization := request.Header.Get(c.headerName)
		if len(authorization) == 0 {
			logger.Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, "no authorization header", "request", request)
			response.WriteHeader(http.StatusForbidden)
			return
		}

		i := strings.IndexByte(authorization, ' ')
		if i < 1 {
			logger.Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, "unexpected authorization header value",
				"request", request, "auth", authorization)
			response.WriteHeader(http.StatusBadRequest)
			return
		}

		key := bascule.Authorization(
			textproto.CanonicalMIMEHeaderKey(authorization[:i]),
		)

		tf, supported := c.authorizations[key]
		if !supported {
			logger.Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, "key not supported", "request", request,
				"key", key, "auth", authorization[i+1:])
			response.WriteHeader(http.StatusForbidden)
			return
		}

		ctx := request.Context()
		token, err := tf.ParseAndValidate(ctx, request, key, authorization[i+1:])
		if err != nil {
			logger.Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, err.Error(), "request", request,
				"key", key, "auth", authorization[i+1:])
			WriteResponse(response, http.StatusUnauthorized, err)
			return
		}

		ctx = bascule.WithAuthentication(
			request.Context(),
			bascule.Authentication{
				Authorization: key,
				Token:         token,
			},
		)
		logger.Log(level.Key(), level.DebugValue(), "msg", "authentication added to context", "request", request,
			"token", token, "key", key)

		next.ServeHTTP(response, request.WithContext(ctx))
	})
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

// New returns an Alice-style constructor which decorates HTTP handlers with security code
func NewConstructor(options ...COption) func(http.Handler) http.Handler {
	c := &constructor{
		headerName:     DefaultHeaderName,
		authorizations: make(map[bascule.Authorization]TokenFactory),
		getLogger:      bascule.GetDefaultLoggerFunc,
	}

	for _, o := range options {
		o(c)
	}

	return c.decorate
}
