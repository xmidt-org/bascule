// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type TokenParserSuite struct {
	TestSuite

	expectedCtx    context.Context
	expectedSource int
	expectedToken  Token
	expectedErr    error
}

func (suite *TokenParserSuite) SetupSuite() {
	suite.expectedCtx = suite.testContext()
	suite.expectedSource = 123
	suite.expectedToken = testToken("expected token")
	suite.expectedErr = errors.New("expected token parser error")
}

func (suite *TokenParserSuite) assertParserResult(actualToken Token, actualErr error) {
	suite.Equal(suite.expectedToken, actualToken)
	suite.Equal(suite.expectedErr, actualErr)
}

func (suite *TokenParserSuite) validateSource(actualSource int) (Token, error) {
	suite.Equal(suite.expectedSource, actualSource)
	return suite.expectedToken, suite.expectedErr
}

func (suite *TokenParserSuite) validateContextSource(actualCtx context.Context, actualSource int) (Token, error) {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.expectedSource, actualSource)
	return suite.expectedToken, suite.expectedErr
}

func (suite *TokenParserSuite) testAsTokenParserSource() {
	suite.Run("Simple", func() {
		suite.assertParserResult(
			AsTokenParser[int](suite.validateSource).
				Parse(suite.expectedCtx, suite.expectedSource),
		)
	})

	suite.Run("CustomType", func() {
		type Custom func(int) (Token, error)
		var cf Custom = Custom(suite.validateSource)

		suite.assertParserResult(
			AsTokenParser[int](cf).
				Parse(suite.expectedCtx, suite.expectedSource),
		)
	})
}

func (suite *TokenParserSuite) testAsTokenParserContextSource() {
	suite.Run("Simple", func() {
		suite.assertParserResult(
			AsTokenParser[int](suite.validateContextSource).
				Parse(suite.expectedCtx, suite.expectedSource),
		)
	})

	suite.Run("CustomType", func() {
		type Custom func(context.Context, int) (Token, error)
		var cf Custom = Custom(suite.validateContextSource)

		suite.assertParserResult(
			AsTokenParser[int](cf).
				Parse(suite.expectedCtx, suite.expectedSource),
		)
	})
}

func (suite *TokenParserSuite) TestAsTokenParser() {
	suite.Run("Source", suite.testAsTokenParserSource)
	suite.Run("ContextSource", suite.testAsTokenParserContextSource)
}

// appendMissing appends a count of mocked TokenParser objects that return
// (nil, ErrorMissingCredentials) and expect this suite's expected input.
func (suite *TokenParserSuite) appendMissing(tps TokenParsers[int], count int) TokenParsers[int] {
	for repeat := 0; repeat < count; repeat++ {
		m := new(mockTokenParser[int])
		m.ExpectParse(suite.expectedCtx, suite.expectedSource).
			Return(nil, ErrMissingCredentials).Once()
		tps = tps.Append(m)
	}

	return tps
}

// appendSuccess appends a single mocked TokenParser that returns success using this
// suite's expected inputs and outputs.
func (suite *TokenParserSuite) appendSuccess(tps TokenParsers[int]) TokenParsers[int] {
	m := new(mockTokenParser[int])
	m.ExpectParse(suite.expectedCtx, suite.expectedSource).
		Return(suite.expectedToken, nil).Once()

	return tps.Append(m)
}

// appendFail appends a single mocked TokenParser that returns a nil token and a failing
// error, using this suite's expected inputs and outputs.
func (suite *TokenParserSuite) appendFail(tps TokenParsers[int]) TokenParsers[int] {
	m := new(mockTokenParser[int])
	m.ExpectParse(suite.expectedCtx, suite.expectedSource).
		Return(nil, suite.expectedErr).Once()

	return tps.Append(m)
}

// appendNoCall appends a count of mocked TokenParser objects that expect no calls to
// be made.  Useful to verify that a TokenParsers instance stops parsing upon
// a successful parse or a non-missing error.
func (suite *TokenParserSuite) appendNoCall(tps TokenParsers[int], count int) TokenParsers[int] {
	for repeat := 0; repeat < count; repeat++ {
		m := new(mockTokenParser[int])
		tps = tps.Append(m)
	}

	return tps
}

// assertTokenParsersSuccess calls Parse and asserts that this suite's expected input occurred and
// that the ultimate token was this suite's expected token with a nil error.
func (suite *TokenParserSuite) assertTokenParsersSuccess(tps TokenParsers[int]) {
	actualToken, actualErr := tps.Parse(suite.expectedCtx, suite.expectedSource)
	suite.Equal(suite.expectedToken, actualToken)
	suite.NoError(actualErr)
	assertTokenParsers(suite.T(), tps...)
}

// assertTokenParsersFail calls Parse and asserts that this suite's expected input occurred and
// that a failure occurred with this suite's expected error.
func (suite *TokenParserSuite) assertTokenParsersFail(tps TokenParsers[int]) {
	actualToken, actualErr := tps.Parse(suite.expectedCtx, suite.expectedSource)
	suite.Nil(actualToken)
	suite.ErrorIs(actualErr, suite.expectedErr)
	assertTokenParsers(suite.T(), tps...)
}

func (suite *TokenParserSuite) testTokenParsersEmpty() {
	var tps TokenParsers[int]
	t, err := tps.Parse(suite.expectedCtx, suite.expectedSource)
	suite.Nil(t)
	suite.ErrorIs(err, ErrNoTokenParsers)
}

func (suite *TokenParserSuite) testTokenParsersSuccess() {
	for _, count := range []int{1, 2, 5, 8} {
		suite.Run(fmt.Sprintf("count=%d", count), func() {
			tps := suite.appendMissing(nil, count/2) // half the parsers report missing, i.e. unsupported
			tps = suite.appendSuccess(tps)
			tps = suite.appendNoCall(tps, count-len(tps))
			suite.assertTokenParsersSuccess(tps)
		})
	}
}

func (suite *TokenParserSuite) testTokenParsersFail() {
	for _, count := range []int{1, 2, 5, 8} {
		suite.Run(fmt.Sprintf("count=%d", count), func() {
			tps := suite.appendMissing(nil, count/2) // half the parsers report missing, i.e. unsupported
			tps = suite.appendFail(tps)
			tps = suite.appendNoCall(tps, count-len(tps))
			suite.assertTokenParsersFail(tps)
		})
	}
}

func (suite *TokenParserSuite) TestTokenParsers() {
	suite.Run("Empty", suite.testTokenParsersEmpty)
	suite.Run("Success", suite.testTokenParsersSuccess)
	suite.Run("Fail", suite.testTokenParsersFail)
}

func TestTokenParser(t *testing.T) {
	suite.Run(t, new(TokenParserSuite))
}
