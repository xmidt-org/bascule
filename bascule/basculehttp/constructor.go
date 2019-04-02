package basculehttp

import (
	"net/http"
	"net/textproto"
	"strings"

	"github.com/Comcast/comcast-bascule/bascule"
)

const (
	DefaultHeaderName = "Authorization"
)

type constructor struct {
	headerName     string
	authorizations map[bascule.Authorization]TokenFactory
}

func (c *constructor) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get(c.headerName)
		if len(authorization) == 0 {
			response.WriteHeader(http.StatusForbidden)
			return
		}

		i := strings.IndexByte(authorization, ' ')
		if i < 1 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}

		key := bascule.Authorization(
			textproto.CanonicalMIMEHeaderKey(authorization[:i]),
		)

		tf, supported := c.authorizations[key]
		if !supported {
			response.WriteHeader(http.StatusForbidden)
			return
		}

		ctx := request.Context()
		token, err := tf.ParseAndValidate(ctx, request, key, authorization[i+1:])
		if err != nil {
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

// New returns an Alice-style constructor which decorates HTTP handlers with security code
func NewConstructor(options ...COption) func(http.Handler) http.Handler {
	c := &constructor{
		headerName:     DefaultHeaderName,
		authorizations: make(map[bascule.Authorization]TokenFactory),
	}

	for _, o := range options {
		o(c)
	}

	return c.decorate
}
