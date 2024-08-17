// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule/v1"
)

type MiddlewareTestSuite struct {
	suite.Suite
}

// newAuthorizationParser creates an AuthorizationParser that is expected to be valid.
// Assertions as to validity are made prior to returning.
func (suite *MiddlewareTestSuite) newAuthorizationParser(opts ...AuthorizationParserOption) *AuthorizationParser {
	ap, err := NewAuthorizationParser(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(ap)
	return ap
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

func (suite *MiddlewareTestSuite) assertChallenge(c Challenge, err error) Challenge {
	suite.Require().NoError(err)
	return c
}

func (suite *MiddlewareTestSuite) testBasicAuthSuccess() {
	const (
		expectedPrincipal = "test"
		expectedPassword  = "test"
	)

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
							suite.Equal("/test", request.URL.String())
							suite.Equal(expectedPrincipal, token.Principal())
							suite.Require().Implements((*BasicToken)(nil), token)
							suite.Equal(expectedPrincipal, token.(BasicToken).UserName())
							suite.Equal(expectedPassword, token.(BasicToken).Password())
							return nil
						},
					),
					bascule.WithAuthorizeListenerFuncs(
						func(e bascule.AuthorizeEvent[*http.Request]) {
							suite.Equal("/test", e.Resource.URL.String())
							suite.Require().NotNil(e.Token)
							suite.NoError(e.Err)
							authorizeEvent = true
						},
					),
				),
			),
		)

		response = httptest.NewRecorder()
		request  = httptest.NewRequest("GET", "/test", nil)

		h = m.ThenFunc(func(response http.ResponseWriter, request *http.Request) {
			suite.Equal("/test", request.URL.String())
			response.WriteHeader(299)
		})
	)

	request.SetBasicAuth(expectedPrincipal, expectedPassword)
	h.ServeHTTP(response, request)
	suite.Equal(299, response.Code)
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
							suite.Equal("/test", e.Source.URL.String())
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
		request  = httptest.NewRequest("GET", "/test", nil)

		h = m.ThenFunc(func(response http.ResponseWriter, request *http.Request) {
			suite.Equal("/test", request.URL.String())
			response.WriteHeader(299)
		})
	)

	h.ServeHTTP(response, request)
	suite.Equal(http.StatusUnauthorized, response.Code)

	suite.Equal(
		`Basic realm="test" charset="UTF-8"`,
		response.HeaderMap.Get(WWWAuthenticateHeader),
	)

	suite.True(authenticateEvent)
}

func (suite *MiddlewareTestSuite) TestBasicAuth() {
	suite.Run("Success", suite.testBasicAuthSuccess)
	suite.Run("Challenge", suite.testBasicAuthChallenge)
}

func TestMiddleware(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}
