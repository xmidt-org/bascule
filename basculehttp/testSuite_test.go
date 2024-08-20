// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

const (
	expectedPrincipal = "testPrincipal"
	expectedPassword  = "test_password"
)

// TestSuite is a common suite that exposes some useful behaviors.
type TestSuite struct {
	suite.Suite
}

// newRequest creates a standardized test request, devoid of any authorization.
func (suite *TestSuite) newRequest() *http.Request {
	return httptest.NewRequest("GET", "/test", nil)
}

// assertRequest asserts that the given request matches the one created by newRequest.
func (suite *TestSuite) assertBasicAuthRequest(request *http.Request) {
	suite.Require().NotNil(request)
	suite.Equal("GET", request.Method)
	suite.Equal("/test", request.URL.String())
}

// newBasicAuthRequest creates a new test request configured with valid basic auth.
func (suite *TestSuite) newBasicAuthRequest() *http.Request {
	request := suite.newRequest()
	request.SetBasicAuth(expectedPrincipal, expectedPassword)
	return request
}

// basicAuth produces a formatted basic authorization string using this suite's expectations.
func (suite *TestSuite) basicAuth() string {
	return BasicAuth(expectedPrincipal, expectedPassword)
}

// assertBasicToken asserts that the token matches the one created by newBasicToken.
func (suite *TestSuite) assertBasicToken(token bascule.Token) {
	suite.Require().NotNil(token)
	suite.Equal(expectedPrincipal, token.Principal())
	suite.Require().Implements((*BasicToken)(nil), token)
	suite.Equal(expectedPrincipal, token.(BasicToken).UserName())
	suite.Equal(expectedPassword, token.(BasicToken).Password())
}

// newAuthorizationParser creates an AuthorizationParser that is expected to be valid.
// Assertions as to validity are made prior to returning.
func (suite *TestSuite) newAuthorizationParser(opts ...AuthorizationParserOption) *AuthorizationParser {
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
