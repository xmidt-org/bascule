// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/sallust"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

const (
	// DefaultHeaderName is the http header to get the authorization
	// information from.
	DefaultHeaderName = "Authorization"

	// DefaultHeaderDelimiter is the character between the authorization and
	// its key.
	DefaultHeaderDelimiter = " "

	// BasicAuthorization follows the RFC spec for Oauth 2.0 and is a canonical
	// MIME header for Basic Authorization.
	BasicAuthorization bascule.Authorization = "Basic"

	// BasicAuthorization follows the RFC spec for Oauth 2.0 and is a canonical
	// MIME header for Basic Authorization.
	BearerAuthorization bascule.Authorization = "Bearer"
)

var (
	errNoAuthHeader    = errors.New("no authorization header")
	errBadAuthHeader   = errors.New("unexpected authorization header value")
	errKeyNotSupported = errors.New("key not supported")
)

// TokenFactory is a strategy interface responsible for creating and validating
// a secure Token.
type TokenFactory interface {
	ParseAndValidate(context.Context, *http.Request, bascule.Authorization, string) (bascule.Token, error)
}

// COption is any function that modifies the constructor - used to configure
// the constructor.
type COption func(*constructor)

// COptionsIn is the uber.fx wired struct needed to group together the
// options for the bascule constructor middleware, which does initial parsing
// of the auth provided.
type COptionsIn struct {
	fx.In
	Options []COption `group:"bascule_constructor_options"`
}

type constructor struct {
	headerName          string
	headerDelimiter     string
	authorizations      map[bascule.Authorization]TokenFactory
	getLogger           func(context.Context) *zap.Logger
	parseURL            ParseURL
	onErrorResponse     OnErrorResponse
	onErrorHTTPResponse OnErrorHTTPResponse
}

func (c *constructor) authenticationOutput(logger *zap.Logger, request *http.Request) (bascule.Authentication, ErrorResponseReason, error) {
	urlVal := *request.URL // copy the URL before modifying it
	u, err := c.parseURL(&urlVal)
	if err != nil {
		return bascule.Authentication{}, GetURLFailed, fmt.Errorf("failed to parse url '%v': %v", request.URL, err)
	}
	authorization := request.Header.Get(c.headerName)
	if len(authorization) == 0 {
		return bascule.Authentication{}, MissingHeader, errNoAuthHeader
	}
	i := strings.Index(authorization, c.headerDelimiter)
	if i < 1 {
		return bascule.Authentication{}, InvalidHeader, errBadAuthHeader
	}

	key := bascule.Authorization(authorization[:i])
	tf, supported := c.authorizations[key]
	if !supported {
		return bascule.Authentication{}, KeyNotSupported, fmt.Errorf("%w: [%v]", errKeyNotSupported, key)
	}

	ctx := request.Context()
	token, err := tf.ParseAndValidate(ctx, request, key, authorization[i+len(c.headerDelimiter):])
	if err != nil {
		return bascule.Authentication{}, ParseFailed, fmt.Errorf("failed to parse and validate token: %v", err)
	}

	return bascule.Authentication{
		Authorization: key,
		Token:         token,
		Request: bascule.Request{
			URL:    u,
			Method: request.Method,
		},
	}, -1, nil
}

func (c *constructor) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := c.getLogger(r.Context())
		if logger == nil {
			logger = sallust.Get(r.Context())
		}
		auth, errReason, err := c.authenticationOutput(logger, r)
		if err != nil {
			logger.Error(err.Error(), zap.String("auth", r.Header.Get(c.headerName)))
			c.onErrorResponse(errReason, err)
			c.onErrorHTTPResponse(w, errReason)
			return
		}
		ctx := bascule.WithAuthentication(r.Context(), auth)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// NewConstructor creates an Alice-style decorator function that acts as
// middleware: parsing the http request to get a Token, which is added to the
// context.
func NewConstructor(options ...COption) func(http.Handler) http.Handler {
	c := &constructor{
		headerName:          DefaultHeaderName,
		headerDelimiter:     DefaultHeaderDelimiter,
		authorizations:      make(map[bascule.Authorization]TokenFactory),
		getLogger:           sallust.Get,
		parseURL:            DefaultParseURLFunc,
		onErrorResponse:     DefaultOnErrorResponse,
		onErrorHTTPResponse: DefaultOnErrorHTTPResponse,
	}

	for _, o := range options {
		if o == nil {
			continue
		}
		o(c)
	}

	return c.decorate
}

// WithHeaderName sets the headername and verifies it's valid.  The headername
// is the name of the header to get the authorization information from.
func WithHeaderName(headerName string) COption {
	return func(c *constructor) {
		if len(headerName) > 0 {
			c.headerName = headerName
		}
	}
}

// WithHeaderDelimiter sets the value expected between the authorization key and token.
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
		if tf != nil {
			c.authorizations[key] = tf
		}
	}
}

// WithCLogger sets the function to use to get the logger from the context.
// If no logger is set, nothing is logged.
func WithCLogger(getLogger func(context.Context) *zap.Logger) COption {
	return func(c *constructor) {
		if getLogger != nil {
			c.getLogger = getLogger
		}
	}
}

// WithParseURLFunc sets the function to use to make any changes to the URL
// before it is added to the context.
func WithParseURLFunc(parseURL ParseURL) COption {
	return func(c *constructor) {
		if parseURL != nil {
			c.parseURL = parseURL
		}
	}
}

// WithCErrorResponseFunc sets the function that is called when an error occurs.
func WithCErrorResponseFunc(f OnErrorResponse) COption {
	return func(c *constructor) {
		if f != nil {
			c.onErrorResponse = f
		}
	}
}

// WithCErrorHTTPResponseFunc sets the function whose job is to translate
// bascule errors into the appropriate HTTP response.
func WithCErrorHTTPResponseFunc(f OnErrorHTTPResponse) COption {
	return func(c *constructor) {
		if f != nil {
			c.onErrorHTTPResponse = f
		}
	}
}

// ProvideConstructor is a helper function for wiring up a basculehttp
// constructor with uber fx.  Any options or optional values added with uber fx
// will be used to create the constructor.
func ProvideConstructor() fx.Option {
	return fx.Options(
		ProvideOnErrorHTTPResponse(),
		ProvideParseURL(),
		fx.Provide(
			fx.Annotated{
				Name: "alice_constructor",
				Target: func(in COptionsIn) alice.Constructor {
					return NewConstructor(in.Options...)
				},
			},
		),
	)
}
