// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/xmidt-org/bascule"
)

// withAuthorizationParserOptionErr is an option that returns an error.
// These tests need this since no options currently return errors
// for an AuthorizationParser.
func withAuthorizationParserOptionErr(err error) AuthorizationParserOption {
	return authorizationParserOptionFunc(func(*AuthorizationParser) error {
		return err
	})
}

type AuthorizationTestSuite struct {
	TestSuite
}

// newAuthorizationParser produces a parser from a set of options that must assert as valid.
func (suite *AuthorizationTestSuite) newAuthorizationParser(opts ...AuthorizationParserOption) *AuthorizationParser {
	ap, err := NewAuthorizationParser(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(ap)
	return ap
}

func (suite *AuthorizationTestSuite) TestParseAuthorization() {
	tests := []struct {
		name            string
		authHeaderValue string
		err             error
	}{
		{
			name:            "success",
			authHeaderValue: "Basic foobar",
		},
		{
			name:            "scheme only failure",
			authHeaderValue: "Basic",
			err:             ErrInvalidAuthorization,
		},
		{
			name:            "scheme and whitespace failure",
			authHeaderValue: "Basic ",
			err:             ErrInvalidAuthorization,
		},
		{
			name: "empty string failure",
			err:  ErrInvalidAuthorization,
		},
	}
	for _, tc := range tests {
		suite.Run(tc.name, func() {
			s, v, err := ParseAuthorization(tc.authHeaderValue)
			if tc.err != nil {
				suite.ErrorIs(err, tc.err)

				return
			}

			suite.Require().NoError(err)
			suite.NotEmpty(s)
			suite.NotEmpty(v)
		})
	}
}

func (suite *AuthorizationTestSuite) TestBasicAuthSuccess() {
	suite.Run("DefaultHeader", func() {
		var (
			ap = suite.newAuthorizationParser(
				WithBasic(),
			)

			request = suite.newBasicAuthRequest()
		)

		token, err := ap.Parse(context.Background(), request)
		suite.Require().NoError(err)
		suite.assertBasicToken(token)
	})

	suite.Run("Custom", func() {
		var (
			ap = suite.newAuthorizationParser(
				WithAuthorizationHeader("Auth-Custom"),
				WithScheme(Scheme("Custom"), BasicTokenParser{}),
			)

			request = suite.newRequest()
		)

		request.Header.Set("Auth-Custom", "Custom "+suite.basicAuth())
		token, err := ap.Parse(context.Background(), request)
		suite.Require().NoError(err)
		suite.assertBasicToken(token)
	})
}

func (suite *AuthorizationTestSuite) TestMissingCredentials() {
	var (
		ap = suite.newAuthorizationParser(
			WithBasic(),
		)

		request = suite.newRequest()
	)

	token, err := ap.Parse(context.Background(), request)
	suite.Require().ErrorIs(err, bascule.ErrMissingCredentials)
	suite.Nil(token)
}

func (suite *AuthorizationTestSuite) TestInvalidCredentials() {
	var (
		ap = suite.newAuthorizationParser(
			WithBasic(),
		)

		request = suite.newRequest()
	)

	request.Header.Set(DefaultAuthorizationHeader, "\t")
	token, err := ap.Parse(context.Background(), request)
	suite.Require().ErrorIs(err, bascule.ErrInvalidCredentials)
	suite.Nil(token)
}

func (suite *AuthorizationTestSuite) TestUnsupportedScheme() {
	var (
		ap = suite.newAuthorizationParser(
			WithBasic(),
		)

		request = suite.newRequest()
	)

	request.Header.Set(DefaultAuthorizationHeader, "Unsupported xyz")
	token, err := ap.Parse(context.Background(), request)
	suite.Nil(token)

	var use *UnsupportedSchemeError
	suite.Require().ErrorAs(err, &use)
	suite.Equal(Scheme("Unsupported"), use.Scheme)
}

func (suite *AuthorizationTestSuite) TestOptionError() {
	expectedErr := errors.New("expected")
	ap, err := NewAuthorizationParser(withAuthorizationParserOptionErr(expectedErr))
	suite.Require().ErrorIs(err, expectedErr)
	suite.Nil(ap)
}

// detailedScheme is a scheme parser whose ParseWithDetails reports a token
// with an error, and whose Parse reports none.
type detailedScheme struct{ token bascule.Token }

func (ds detailedScheme) Parse(context.Context, string) (bascule.Token, error) {
	return nil, bascule.ErrBadCredentials
}

func (ds detailedScheme) ParseWithDetails(context.Context, string) (bascule.Token, error) {
	return ds.token, bascule.ErrBadCredentials
}

// TestParseWithDetails verifies the scheme's ParseWithDetails is used when it
// has one, and that Parse never returns the token it reports.
func (suite *AuthorizationTestSuite) TestParseWithDetails() {
	expected := bascule.StubToken("rejected")
	ap := suite.newAuthorizationParser(WithScheme("Test", detailedScheme{token: expected}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Test value")

	token, err := ap.ParseWithDetails(context.Background(), request)
	suite.Require().ErrorIs(err, bascule.ErrBadCredentials)
	suite.Equal(expected, token)

	token, err = ap.Parse(context.Background(), request)
	suite.Require().ErrorIs(err, bascule.ErrBadCredentials)
	suite.Nil(token)
}

// TestParseWithDetailsPlainScheme verifies a scheme parser without
// ParseWithDetails is parsed as usual, including the errors before it.
func (suite *AuthorizationTestSuite) TestParseWithDetailsPlainScheme() {
	ap := suite.newAuthorizationParser(WithBasic())

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := ap.ParseWithDetails(context.Background(), request)
	suite.Require().ErrorIs(err, bascule.ErrMissingCredentials)

	request.Header.Set("Authorization", "Digest abc")
	_, err = ap.ParseWithDetails(context.Background(), request)
	suite.Require().Error(err)

	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("joe:secret")))
	token, err := ap.ParseWithDetails(context.Background(), request)
	suite.Require().NoError(err)
	suite.Equal("joe", token.Principal())
}

func TestAuthorization(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(AuthorizationTestSuite))
}
