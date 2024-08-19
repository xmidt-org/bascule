// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
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

func (suite *AuthorizationTestSuite) TestBasicAuthSuccess() {
	suite.Run("DefaultHeader", func() {
		var (
			ap = suite.newAuthorizationParser(
				WithBasic(),
			)

			request = suite.newBasicAuthRequest()
		)

		token, err := ap.Parse(context.Background(), request)
		suite.NoError(err)
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
		suite.NoError(err)
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
	suite.ErrorIs(err, bascule.ErrMissingCredentials)
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
	suite.ErrorIs(err, bascule.ErrInvalidCredentials)
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
	suite.ErrorIs(err, expectedErr)
	suite.Nil(ap)
}

func TestAuthorization(t *testing.T) {
	suite.Run(t, new(AuthorizationTestSuite))
}
