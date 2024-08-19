// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule/v1"
)

type MiddlewareTestSuite struct {
	TestSuite
}

// newAuthenticator creates a bascule.Authenticator that is expected to be valid.
// Assertions as to validity are made prior to returning.
func (suite *MiddlewareTestSuite) newAuthenticator(opts ...bascule.AuthenticatorOption[*http.Request]) *bascule.Authenticator[*http.Request] {
	a, err := NewAuthenticator(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(a)
	return a
}

// newAuthorizer creates a bascule.Authorizer that is expected to be valid.
// Assertions as to validity are made prior to returning.
func (suite *MiddlewareTestSuite) newAuthorizer(opts ...bascule.AuthorizerOption[*http.Request]) *bascule.Authorizer[*http.Request] {
	a, err := NewAuthorizer(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(a)
	return a
}

// newMiddleware creates a Middleware that is expected to be valid.
// Assertions as to validity are made prior to returning.
func (suite *MiddlewareTestSuite) newMiddleware(opts ...MiddlewareOption) *Middleware {
	m, err := NewMiddleware(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(m)
	return m
}

// serveHTTPFunc is a standard, non-error handler function that sets the normalResponseCode.
func (suite *MiddlewareTestSuite) serveHTTPFunc(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/octet-stream")
	response.WriteHeader(299)
	response.Write([]byte("normal response"))
}

// assertNormalResponse asserts that the Middleware allowed the response from serveHTTPFunc.
func (suite *MiddlewareTestSuite) assertNormalResponse(response *httptest.ResponseRecorder) {
	suite.Equal(299, response.Code)
	suite.Equal("application/octet-stream", response.HeaderMap.Get("Content-Type"))
	suite.Equal("normal response", response.Body.String())
}

// serveHTTPNoCall is a handler function that should be blocked by the Middleware.
func (suite *MiddlewareTestSuite) serveHTTPNoCall(http.ResponseWriter, *http.Request) {
	suite.Fail("The handler should not have been called")
}

func (suite *MiddlewareTestSuite) assertChallenge(c Challenge, err error) Challenge {
	suite.Require().NoError(err)
	return c
}

func (suite *MiddlewareTestSuite) TestUseAuthenticatorError() {
	m, err := NewMiddleware(
		UseAuthenticator(
			bascule.NewAuthenticator[*http.Request](), // no token parsers
		),
	)

	suite.ErrorIs(err, bascule.ErrNoTokenParsers)
	suite.Nil(m)
}

func (suite *MiddlewareTestSuite) TestUseAuthorizerError() {
	expectedErr := errors.New("expected")
	m, err := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(
					suite.newAuthorizationParser(WithBasic()),
				),
			),
		),
		UseAuthorizer(nil, expectedErr),
	)

	suite.ErrorIs(err, expectedErr)
	suite.Nil(m)
}

func (suite *MiddlewareTestSuite) TestNoAuthenticatorWithAuthorizer() {
	m, err := NewMiddleware(
		WithAuthorizer(
			suite.newAuthorizer(),
		),
	)

	suite.Nil(m)
	suite.ErrorIs(err, ErrNoAuthenticator)
}

func (suite *MiddlewareTestSuite) TestThen() {
	suite.Run("NilHandler", func() {
		var (
			m = suite.newMiddleware(
				WithAuthenticator(
					suite.newAuthenticator(
						bascule.WithTokenParsers(
							suite.newAuthorizationParser(WithBasic()),
						),
					),
				),
			)

			h = m.Then(nil)

			response = httptest.NewRecorder()
			request  = suite.newBasicAuthRequest()
		)

		h.ServeHTTP(response, request)
		suite.Equal(http.StatusNotFound, response.Code) // use the unconfigured http.DefaultServeMux
	})

	suite.Run("NoDecoration", func() {
		var (
			m = suite.newMiddleware()
			h = m.Then(http.HandlerFunc(
				suite.serveHTTPFunc,
			))

			response = httptest.NewRecorder()
			request  = suite.newRequest()
		)

		h.ServeHTTP(response, request)
		suite.assertNormalResponse(response)
	})
}

func (suite *MiddlewareTestSuite) TestThenFunc() {
	suite.Run("NilHandlerFunc", func() {
		var (
			m = suite.newMiddleware(
				WithAuthenticator(
					suite.newAuthenticator(
						bascule.WithTokenParsers(
							suite.newAuthorizationParser(WithBasic()),
						),
					),
				),
			)

			h = m.ThenFunc(nil)

			response = httptest.NewRecorder()
			request  = suite.newBasicAuthRequest()
		)

		h.ServeHTTP(response, request)
		suite.Equal(http.StatusNotFound, response.Code) // use the unconfigured http.DefaultServeMux
	})
}

func (suite *MiddlewareTestSuite) TestCustomErrorRendering() {
	var (
		m = suite.newMiddleware(
			WithAuthenticator(
				suite.newAuthenticator(
					bascule.WithTokenParsers(
						suite.newAuthorizationParser(WithBasic()),
					),
				),
			),
			WithErrorStatusCoder(
				func(request *http.Request, err error) int {
					suite.Equal(request.URL.String(), "/test")
					return 567
				},
			),
			WithErrorMarshaler(
				func(request *http.Request, err error) (contentType string, content []byte, marshalErr error) {
					contentType = "text/xml"
					content = []byte("<something/>")
					return
				},
			),
		)

		response = httptest.NewRecorder()
		request  = suite.newRequest()

		h = m.ThenFunc(suite.serveHTTPNoCall)
	)

	h.ServeHTTP(response, request)
	suite.Equal(567, response.Code)
	suite.Equal("text/xml", response.HeaderMap.Get("Content-Type"))
	suite.Equal("<something/>", response.Body.String())
}

func (suite *MiddlewareTestSuite) TestMarshalError() {
	var (
		marshalErr = errors.New("expected marshal error")

		m = suite.newMiddleware(
			WithAuthenticator(
				suite.newAuthenticator(
					bascule.WithTokenParsers(
						suite.newAuthorizationParser(WithBasic()),
					),
				),
			),
			WithErrorStatusCoder(
				func(request *http.Request, err error) int {
					suite.Equal(request.URL.String(), "/test")
					return 567
				},
			),
			WithErrorMarshaler(
				func(request *http.Request, err error) (string, []byte, error) {
					return "", nil, marshalErr
				},
			),
		)

		response = httptest.NewRecorder()
		request  = suite.newRequest()

		h = m.ThenFunc(suite.serveHTTPNoCall)
	)

	h.ServeHTTP(response, request)
	suite.Equal(http.StatusInternalServerError, response.Code)

	mediaType, _, err := mime.ParseMediaType(response.HeaderMap.Get("Content-Type"))
	suite.Require().NoError(err)
	suite.Equal("text/plain", mediaType)
	suite.Equal(marshalErr.Error(), response.Body.String())
}

func (suite *MiddlewareTestSuite) testBasicAuthSuccess() {
	var (
		authenticateEvent = false
		authorizeEvent    = false

		m = suite.newMiddleware(
			WithAuthenticator(
				suite.newAuthenticator(
					bascule.WithTokenParsers(
						suite.newAuthorizationParser(WithBasic()),
					),
					bascule.WithAuthenticateListenerFuncs(
						func(e bascule.AuthenticateEvent[*http.Request]) {
							suite.Equal("/test", e.Source.URL.String())
							suite.Require().NotNil(e.Token)
							suite.NoError(e.Err)
							authenticateEvent = true
						},
					),
				),
			),
			WithAuthorizer(
				suite.newAuthorizer(
					bascule.WithApproverFuncs(
						func(_ context.Context, request *http.Request, token bascule.Token) error {
							suite.assertBasicAuthRequest(request)
							suite.assertBasicToken(token)
							return nil
						},
					),
					bascule.WithAuthorizeListenerFuncs(
						func(e bascule.AuthorizeEvent[*http.Request]) {
							suite.assertBasicAuthRequest(e.Resource)
							suite.assertBasicToken(e.Token)
							authorizeEvent = true
						},
					),
				),
			),
		)

		response = httptest.NewRecorder()
		request  = suite.newBasicAuthRequest()

		h = m.ThenFunc(suite.serveHTTPFunc)
	)

	h.ServeHTTP(response, request)
	suite.assertNormalResponse(response)
	suite.True(authenticateEvent)
	suite.True(authorizeEvent)
}

func (suite *MiddlewareTestSuite) testBasicAuthChallenge() {
	var (
		authenticateEvent = false

		m = suite.newMiddleware(
			WithAuthenticator(
				suite.newAuthenticator(
					bascule.WithTokenParsers(
						suite.newAuthorizationParser(WithBasic()),
					),
					bascule.WithAuthenticateListenerFuncs(
						func(e bascule.AuthenticateEvent[*http.Request]) {
							suite.assertBasicAuthRequest(e.Source)
							suite.ErrorIs(bascule.ErrMissingCredentials, e.Err)
							suite.Nil(e.Token)
							authenticateEvent = true
						},
					),
				),
			),
			WithChallenges(
				suite.assertChallenge(NewBasicChallenge("test", true)),
			),
		)

		response = httptest.NewRecorder()
		request  = suite.newRequest()

		h = m.ThenFunc(suite.serveHTTPNoCall)
	)

	h.ServeHTTP(response, request)
	suite.Equal(http.StatusUnauthorized, response.Code)

	suite.Equal(
		`Basic realm="test" charset="UTF-8"`,
		response.HeaderMap.Get(WWWAuthenticateHeader),
	)

	suite.True(authenticateEvent)
}

func (suite *MiddlewareTestSuite) testBasicAuthInvalid() {
	var (
		m = suite.newMiddleware(
			WithAuthenticator(
				suite.newAuthenticator(
					bascule.WithTokenParsers(
						suite.newAuthorizationParser(WithBasic()),
					),
				),
			),
		)

		response = httptest.NewRecorder()
		request  = suite.newRequest()

		h = m.ThenFunc(suite.serveHTTPNoCall)
	)

	request.Header.Set("Authorization", "Basic this is most definitely not a valid basic auth string")
	h.ServeHTTP(response, request)
	suite.Equal(http.StatusBadRequest, response.Code)
}

func (suite *MiddlewareTestSuite) testBasicAuthAuthorizerError() {
	var (
		expectedErr = errors.New("expected error")

		m = suite.newMiddleware(
			WithAuthenticator(
				suite.newAuthenticator(
					bascule.WithTokenParsers(
						suite.newAuthorizationParser(WithBasic()),
					),
				),
			),
			WithAuthorizer(
				suite.newAuthorizer(
					bascule.WithApproverFuncs(
						func(_ context.Context, resource *http.Request, token bascule.Token) error {
							suite.assertBasicAuthRequest(resource)
							suite.assertBasicToken(token)
							return expectedErr
						},
					),
				),
			),
		)

		response = httptest.NewRecorder()
		request  = suite.newBasicAuthRequest()

		h = m.ThenFunc(suite.serveHTTPNoCall)
	)

	h.ServeHTTP(response, request)
	suite.Equal(http.StatusForbidden, response.Code)
	suite.Equal(expectedErr.Error(), response.Body.String())
}

func (suite *MiddlewareTestSuite) TestBasicAuth() {
	suite.Run("Success", suite.testBasicAuthSuccess)
	suite.Run("Challenge", suite.testBasicAuthChallenge)
	suite.Run("Invalid", suite.testBasicAuthInvalid)
	suite.Run("AuthorizerError", suite.testBasicAuthAuthorizerError)
}

func TestMiddleware(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}
