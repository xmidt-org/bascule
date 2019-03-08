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

type decorator struct {
	headerName     string
	authorizations map[bascule.Authorization]TokenFactory
}

func (d *decorator) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get(d.headerName)
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

		tf, supported := d.authorizations[key]
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
				key,
				token,
			},
		)

		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

type Option func(*decorator)

func WithHeaderName(headerName string) Option {
	return func(d *decorator) {
		if len(headerName) > 0 {
			d.headerName = headerName
		} else {
			d.headerName = DefaultHeaderName
		}
	}
}

func WithTokenFactory(key bascule.Authorization, tf TokenFactory) Option {
	return func(d *decorator) {
		d.authorizations[key] = tf
	}
}

// New returns an Alice-style constructor which decorates HTTP handlers with security code
func New(options ...Option) func(http.Handler) http.Handler {
	d := &decorator{
		headerName:     DefaultHeaderName,
		authorizations: make(map[bascule.Authorization]TokenFactory),
	}

	for _, o := range options {
		o(d)
	}

	return d.decorate
}
