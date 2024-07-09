// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type TokenParsersSuite struct {
	TestSuite
}

func (suite *TokenParsersSuite) assertUnsupportedScheme(scheme Scheme, err error) {
	var use *UnsupportedSchemeError
	if suite.ErrorAs(err, &use) {
		suite.Equal(scheme, use.Scheme)
	}
}

func (suite *TokenParsersSuite) testParseEmpty() {
	var tp TokenParsers[string]

	// legal, but will always fail
	token, err := tp.Parse(context.Background(), "doesnotmatter", suite.testCredentials())
	suite.Nil(token)
	suite.assertUnsupportedScheme(testScheme, err)
}

func (suite *TokenParsersSuite) testParseUnsupported() {
	var tp TokenParsers[string]
	tp.Register(
		Scheme("Supported"),
		TokenParserFunc[string](
			func(context.Context, string, Credentials) (Token, error) {
				suite.Fail("TokenParser should not have been called")
				return nil, nil
			},
		),
	)

	token, err := tp.Parse(context.Background(), "doesnotmatter", suite.testCredentials())
	suite.Nil(token)
	suite.assertUnsupportedScheme(testScheme, err)
}

func (suite *TokenParsersSuite) testParseSupported() {
	var (
		expectedErr = errors.New("expected Parse error")

		testCtx         = suite.testContext()
		testCredentials = suite.testCredentials()
	)

	var tp TokenParsers[string]
	tp.Register(
		testCredentials.Scheme,
		TokenParserFunc[string](
			func(ctx context.Context, _ string, c Credentials) (Token, error) {
				suite.Equal(testCtx, ctx)
				suite.Equal(testCredentials, c)
				return suite.testToken(), expectedErr
			},
		),
	)

	token, err := tp.Parse(testCtx, "doesnotmatter", testCredentials)
	suite.Equal(suite.testToken(), token)
	suite.Same(expectedErr, err)
}

func (suite *TokenParsersSuite) TestParse() {
	suite.Run("Empty", suite.testParseEmpty)
	suite.Run("Unsupported", suite.testParseUnsupported)
	suite.Run("Supported", suite.testParseSupported)
}

func TestTokenParsers(t *testing.T) {
	suite.Run(t, new(TokenParsersSuite))
}
