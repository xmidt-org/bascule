// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
)

type TokenSuite struct {
	suite.Suite
}

func (suite *TokenSuite) TestMultiToken() {
	suite.Run("Empty", func() {
		var mt MultiToken
		suite.Empty(mt.Principal())
		suite.Empty(mt.Unwrap())
	})

	suite.Run("One", func() {
		t := StubToken("test")
		mt := MultiToken{t}
		suite.Equal(t.Principal(), mt.Principal())

		unwrapped := mt.Unwrap()
		suite.Require().Len(unwrapped, 1)
		suite.Equal(t, unwrapped[0])
	})

	suite.Run("Several", func() {
		var (
			m1 = StubToken("test")
			m2 = StubToken("another")
			m3 = StubToken("and another")
		)

		mt := MultiToken{m1, m2, m3}
		suite.Equal(m1.Principal(), mt.Principal())

		unwrapped := mt.Unwrap()
		suite.Require().Len(unwrapped, 3)
		suite.Equal(m1, unwrapped[0])
		suite.Equal(m2, unwrapped[1])
		suite.Equal(m3, unwrapped[2])
	})
}

func (suite *TokenSuite) TestJoinTokens() {
	suite.Run("Nil", func() {
		suite.Nil(JoinTokens())
		suite.Nil(JoinTokens(nil))
		suite.Nil(JoinTokens(nil, nil))
		suite.Nil(JoinTokens(nil, nil, nil))
	})

	suite.Run("NonNil", func() {
		testCases := []struct {
			tokens         []Token
			expectedUnwrap []Token
		}{
			{
				tokens:         []Token{StubToken("test")},
				expectedUnwrap: nil,
			},
			{
				tokens:         []Token{nil, StubToken("test")},
				expectedUnwrap: nil,
			},
			{
				tokens:         []Token{StubToken("test"), nil},
				expectedUnwrap: nil,
			},
			{
				tokens:         []Token{nil, StubToken("test"), nil},
				expectedUnwrap: nil,
			},
			{
				tokens:         []Token{StubToken("test"), StubToken("another"), StubToken("yet another")},
				expectedUnwrap: []Token{StubToken("test"), StubToken("another"), StubToken("yet another")},
			},
			{
				tokens:         []Token{StubToken("test"), nil, StubToken("another"), StubToken("yet another")},
				expectedUnwrap: []Token{StubToken("test"), StubToken("another"), StubToken("yet another")},
			},
		}

		for i, testCase := range testCases {
			suite.Run(strconv.Itoa(i), func() {
				joined := JoinTokens(testCase.tokens...)
				suite.Equal("test", joined.Principal())
				suite.Equal(
					testCase.expectedUnwrap,
					UnwrapToken(joined),
				)
			})
		}
	})
}

func (suite *TokenSuite) TestUnwrapToken() {
	suite.Run("Nil", func() {
		suite.Nil(UnwrapToken(nil))
	})

	suite.Run("Simple", func() {
		suite.Nil(
			UnwrapToken(StubToken("solo")),
		)
	})

	suite.Run("Scalar", func() {
		t := StubToken("test")
		m := new(mockTokenUnwrapOne)
		m.ExpectUnwrap(t).Once()

		suite.Equal([]Token{t}, UnwrapToken(m))
		m.AssertExpectations(suite.T())
	})

	suite.Run("Multi", func() {
		t1 := StubToken("test")
		t2 := StubToken("another")
		m := new(mockTokenUnwrapMany)
		m.ExpectUnwrap(t1, t2).Once()

		suite.Equal([]Token{t1, t2}, UnwrapToken(m))
		m.AssertExpectations(suite.T())
	})
}

func (suite *TokenSuite) testTokenAsNilToken() {
	var target int // won't matter
	suite.False(
		TokenAs(nil, &target),
	)
}

func (suite *TokenSuite) testTokenAsNilTarget() {
	m := new(mockToken)
	suite.Panics(func() {
		TokenAs[int](m, nil)
	})

	m.AssertExpectations(suite.T())
}

func (suite *TokenSuite) testTokenAsInvalidTargetType() {
	var invalid int // not an interface and does not implement Token
	m := new(mockToken)
	suite.Panics(func() {
		TokenAs[int](m, &invalid)
	})

	m.AssertExpectations(suite.T())
}

// wrapToken wraps the given token within another, and returns the wrapper.
func (suite *TokenSuite) wrapToken(t Token) Token {
	wrapper := new(mockTokenUnwrapOne)
	wrapper.ExpectUnwrap(t).Maybe()
	return wrapper
}

func (suite *TokenSuite) testTokenAsConcreteType() {
	suite.Run("Trivial", func() {
		var target StubToken
		t := StubToken("test")
		suite.True(TokenAs(t, &target))
		suite.Equal(t, target)
	})

	suite.Run("NoConversion", func() {
		var target StubToken
		m := new(mockToken)
		suite.False(TokenAs(m, &target))
	})

	suite.Run("Chain", func() {
		nested := StubToken("test")
		wrapper := suite.wrapToken(
			suite.wrapToken(nested),
		)

		var target StubToken
		suite.True(TokenAs(wrapper, &target))
		suite.Equal(nested, target)
	})

	suite.Run("Tree", func() {
		nested := StubToken("test")
		wrapper := JoinTokens(new(mockToken), nested, new(mockToken))

		var target StubToken
		suite.True(TokenAs(wrapper, &target))
		suite.Equal(nested, target)
	})
}

func (suite *TokenSuite) testTokenAsInterface() {
	suite.Run("Trivial", func() {
		var target CapabilitiesAccessor
		m := new(mockTokenWithCapabilities)
		suite.True(TokenAs(m, &target))
		suite.Same(m, target)
	})

	suite.Run("NoConversion", func() {
		var target CapabilitiesAccessor
		m := new(mockToken)
		suite.False(TokenAs(m, &target))
	})

	suite.Run("Chain", func() {
		nested := new(mockTokenWithCapabilities)
		wrapper := suite.wrapToken(
			suite.wrapToken(nested),
		)

		var target CapabilitiesAccessor
		suite.True(TokenAs(wrapper, &target))
		suite.Same(nested, target)
	})

	suite.Run("Tree", func() {
		nested := new(mockTokenWithCapabilities)
		wrapper := JoinTokens(new(mockToken), nested, new(mockToken))

		var target CapabilitiesAccessor
		suite.True(TokenAs(wrapper, &target))
		suite.Same(nested, target)
	})
}

func (suite *TokenSuite) TestTokenAs() {
	suite.Run("NilToken", suite.testTokenAsNilToken)
	suite.Run("NilTarget", suite.testTokenAsNilTarget)
	suite.Run("InvalidTargetType", suite.testTokenAsInvalidTargetType)
	suite.Run("ConcreteType", suite.testTokenAsConcreteType)
	suite.Run("Interface", suite.testTokenAsInterface)
}

func TestToken(t *testing.T) {
	suite.Run(t, new(TokenSuite))
}

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
	suite.expectedToken = StubToken("expected token")
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
	initialLen := tps.Len()

	for repeat := 0; repeat < count; repeat++ {
		m := new(mockTokenParser[int])
		m.ExpectParse(suite.expectedCtx, suite.expectedSource).
			Return(nil, ErrMissingCredentials).Once()
		tps = tps.Append(m)
	}

	suite.Require().Equal(initialLen+count, tps.Len())
	return tps
}

// appendSuccess appends a single mocked TokenParser that returns success using this
// suite's expected inputs and outputs.
func (suite *TokenParserSuite) appendSuccess(tps TokenParsers[int]) TokenParsers[int] {
	initialLen := tps.Len()
	m := new(mockTokenParser[int])
	m.ExpectParse(suite.expectedCtx, suite.expectedSource).
		Return(suite.expectedToken, nil).Once()

	tps = tps.Append(m)
	suite.Require().Equal(initialLen+1, tps.Len())
	return tps
}

// appendFail appends a single mocked TokenParser that returns a nil token and a failing
// error, using this suite's expected inputs and outputs.
func (suite *TokenParserSuite) appendFail(tps TokenParsers[int]) TokenParsers[int] {
	initialLen := tps.Len()
	m := new(mockTokenParser[int])
	m.ExpectParse(suite.expectedCtx, suite.expectedSource).
		Return(nil, suite.expectedErr).Once()

	tps = tps.Append(m)
	suite.Require().Equal(initialLen+1, tps.Len())
	return tps
}

// appendNoCall appends a count of mocked TokenParser objects that expect no calls to
// be made.  Useful to verify that a TokenParsers instance stops parsing upon
// a successful parse or a non-missing error.
func (suite *TokenParserSuite) appendNoCall(tps TokenParsers[int], count int) TokenParsers[int] {
	initialLen := tps.Len()
	for repeat := 0; repeat < count; repeat++ {
		m := new(mockTokenParser[int])
		tps = tps.Append(m)
	}

	suite.Require().Equal(initialLen+count, tps.Len())
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

func (suite *TokenParserSuite) TestStubTokenParser() {
	stp := StubTokenParser[int]{
		Token: StubToken("test"),
	}

	token, err := stp.Parse(context.Background(), 123)
	suite.Require().NoError(err)
	suite.Require().NotNil(token)
	suite.Equal(token.Principal(), "test")
}

func TestTokenParser(t *testing.T) {
	suite.Run(t, new(TokenParserSuite))
}
