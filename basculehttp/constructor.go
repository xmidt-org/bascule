/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// ParseURL is a function that modifies the url given then returns it.
type ParseURL func(*url.URL) (*url.URL, error)

// DefaultParseURLFunc does nothing.  It returns the same url it received.
func DefaultParseURLFunc(u *url.URL) (*url.URL, error) {
	return u, nil
}

// CreateRemovePrefixURLFunc parses the URL by removing the prefix specified.
func CreateRemovePrefixURLFunc(prefix string, next ParseURL) ParseURL {
	return func(u *url.URL) (*url.URL, error) {
		escapedPath := u.EscapedPath()
		if !strings.HasPrefix(escapedPath, prefix) {
			return nil, errors.New("unexpected URL, did not start with expected prefix")
		}
		u.Path = escapedPath[len(prefix):]
		u.RawPath = escapedPath[len(prefix):]
		return next(u)
	}
}

type constructor struct {
	headerName      string
	headerDelimiter string
	authorizations  map[bascule.Authorization]TokenFactory
	getLogger       func(context.Context) log.Logger
	parseURL        ParseURL
	onErrorResponse OnErrorResponse
}

func (c *constructor) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		logger := c.getLogger(request.Context())
		if logger == nil {
			logger = defaultGetLoggerFunc(request.Context())
		}

		urlVal := *request.URL // copy the URL before modifying it
		u, err := c.parseURL(&urlVal)
		if err != nil {
			c.error(logger, GetURLFailed, "", emperror.WrapWith(err, "failed to get URL", "URL", request.URL))
			WriteResponse(response, http.StatusForbidden, err)
			return
		}

		authorization := request.Header.Get(c.headerName)
		if len(authorization) == 0 {
			c.error(logger, MissingHeader, "", errNoAuthHeader)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		i := strings.Index(authorization, c.headerDelimiter)
		if i < 1 {
			c.error(logger, InvalidHeader, authorization, errBadAuthHeader)
			response.WriteHeader(http.StatusBadRequest)
			return
		}

		key := bascule.Authorization(authorization[:i])
		tf, supported := c.authorizations[key]
		if !supported {
			c.error(logger, KeyNotSupported, authorization, fmt.Errorf("%w: [%v]", errKeyNotSupported, key))
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
					URL:    u,
					Method: request.Method,
				},
			},
		)
		logger.Log(level.Key(), level.DebugValue(), "msg", "authentication added to context",
			"token", token, "key", key)

		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func (c *constructor) error(logger log.Logger, e ErrorResponseReason, auth string, err error) {
	log.With(logger, emperror.Context(err)...).Log(level.Key(), level.ErrorValue(), errorKey, err.Error(), "auth", auth)
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
		c.authorizations[key] = tf
	}
}

// WithCLogger sets the function to use to get the logger from the context.
// If no logger is set, nothing is logged.
func WithCLogger(getLogger func(context.Context) log.Logger) COption {
	return func(c *constructor) {
		c.getLogger = getLogger
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
		getLogger:       defaultGetLoggerFunc,
		parseURL:        DefaultParseURLFunc,
		onErrorResponse: DefaultOnErrorResponse,
	}

	for _, o := range options {
		o(c)
	}

	return c.decorate
}
