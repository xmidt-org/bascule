// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthenticatorTestSuite struct {
	suite.Suite
}

// newAuthenticator creates an Authenticator under test, asserting
// that no errors occurred.
func (suite *AuthenticatorTestSuite) newAuthenticator(opts ...AuthenticatorOption[string]) *Authenticator[string] {
	a, err := NewAuthenticator(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(a)
	return a
}

func (suite *AuthenticatorTestSuite) newToken() Token {
	return StubToken("test")
}

func (suite *AuthenticatorTestSuite) newCtx() context.Context {
	type testContextKey struct{}
	return context.WithValue(
		context.Background(),
		testContextKey{},
		"test value",
	)
}

func (suite *AuthenticatorTestSuite) newSource() string {
	return "test source"
}

func (suite *AuthenticatorTestSuite) TestNoOptions() {
	a, err := NewAuthenticator[string]()
	suite.Nil(a)
	suite.ErrorIs(err, ErrNoTokenParsers)
}

func (suite *AuthenticatorTestSuite) TestFullSuccess() {
	var (
		expectedCtx    = suite.newCtx()
		expectedSource = suite.newSource()
		expectedToken  = suite.newToken()

		parser    = new(mockTokenParser[string])
		validator = new(mockValidator[string])
		listener1 = new(mockAuthenticateListener[string])
		listener2 = new(mockAuthenticateListener[string])

		a = suite.newAuthenticator(
			WithTokenParsers(parser),
			WithValidators(validator),
			WithAuthenticateListeners(listener1),
			WithAuthenticateListenerFuncs(listener2.OnEvent),
		)
	)

	parser.ExpectParse(expectedCtx, expectedSource).
		Return(expectedToken, error(nil)).Once()

	validator.ExpectValidate(expectedCtx, expectedSource, expectedToken).
		Return(Token(nil), error(nil)).Once()

	listener1.ExpectOnEvent(AuthenticateEvent[string]{
		Source: expectedSource,
		Token:  expectedToken,
		Err:    nil,
	}).Once()

	listener2.ExpectOnEvent(AuthenticateEvent[string]{
		Source: expectedSource,
		Token:  expectedToken,
		Err:    nil,
	}).Once()

	actualToken, err := a.Authenticate(expectedCtx, expectedSource)
	suite.Equal(expectedToken, actualToken)
	suite.Require().NoError(err)

	parser.AssertExpectations(suite.T())
	validator.AssertExpectations(suite.T())
	listener1.AssertExpectations(suite.T())
	listener2.AssertExpectations(suite.T())
}

func (suite *AuthenticatorTestSuite) TestFullTokenParserFail() {
	var (
		expectedCtx    = suite.newCtx()
		expectedSource = suite.newSource()
		expectedErr    = errors.New("expected")

		parser    = new(mockTokenParser[string])
		validator = new(mockValidator[string])
		listener  = new(mockAuthenticateListener[string])

		a = suite.newAuthenticator(
			WithTokenParsers(parser),
			WithValidators(validator),
			WithAuthenticateListeners(listener),
		)
	)

	parser.ExpectParse(expectedCtx, expectedSource).
		Return(Token(nil), expectedErr).Once()

	listener.ExpectOnEvent(AuthenticateEvent[string]{
		Source: expectedSource,
		Token:  nil,
		Err:    expectedErr,
	}).Once()

	// we don't actually care what is returned for the token
	_, err := a.Authenticate(expectedCtx, expectedSource)
	suite.Require().ErrorIs(err, expectedErr)

	parser.AssertExpectations(suite.T())
	validator.AssertExpectations(suite.T())
	listener.AssertExpectations(suite.T())
}

func (suite *AuthenticatorTestSuite) TestFullValidatorFail() {
	var (
		expectedCtx    = suite.newCtx()
		expectedSource = suite.newSource()
		expectedToken  = suite.newToken()
		expectedErr    = errors.New("expected")

		parser    = new(mockTokenParser[string])
		validator = new(mockValidator[string])
		listener  = new(mockAuthenticateListener[string])

		a = suite.newAuthenticator(
			WithTokenParsers(parser),
			WithValidators(validator),
			WithAuthenticateListeners(listener),
		)
	)

	parser.ExpectParse(expectedCtx, expectedSource).
		Return(expectedToken, error(nil)).Once()

	validator.ExpectValidate(expectedCtx, expectedSource, expectedToken).
		Return(Token(nil), expectedErr).Once()

	listener.ExpectOnEvent(AuthenticateEvent[string]{
		Source: expectedSource,
		Token:  expectedToken,
		Err:    expectedErr,
	}).Once()

	// we don't actually care what is returned for the token
	_, err := a.Authenticate(expectedCtx, expectedSource)
	suite.Require().ErrorIs(err, expectedErr)

	parser.AssertExpectations(suite.T())
	validator.AssertExpectations(suite.T())
	listener.AssertExpectations(suite.T())
}

// TestZeroValueNoParsers verifies an Authenticator not made by NewAuthenticator
// reports that it has no parsers, rather than authenticating anything.
func (suite *AuthenticatorTestSuite) TestZeroValueNoParsers() {
	var a Authenticator[string]

	token, err := a.Authenticate(suite.newCtx(), suite.newSource())
	suite.Require().ErrorIs(err, ErrNoTokenParsers)
	suite.Nil(token)
}

// detailedParser is a DetailedTokenParser that returns what it was given from
// ParseWithDetails, and fails the test if Parse is used.
type detailedParser struct {
	suite *AuthenticatorTestSuite
	token Token
	err   error
}

func (dp detailedParser) Parse(context.Context, string) (Token, error) {
	dp.suite.Fail("Parse should not be used on a DetailedTokenParser")
	return nil, errors.New("Parse should not be used")
}

func (dp detailedParser) ParseWithDetails(context.Context, string) (Token, error) {
	return dp.token, dp.err
}

// TestInvalidToken verifies a token a DetailedTokenParser returns with an
// error is reported to the listeners as the InvalidToken, and is never the
// Token or something Authenticate returns.
func (suite *AuthenticatorTestSuite) TestInvalidToken() {
	var (
		expectedErr = errors.New("expected")
		events      []AuthenticateEvent[string]
		validator   = new(mockValidator[string])
		a           = suite.newAuthenticator(
			WithTokenParsers[string](detailedParser{suite: suite, token: suite.newToken(), err: expectedErr}),
			WithValidators(validator),
			WithAuthenticateListenerFuncs(func(e AuthenticateEvent[string]) { events = append(events, e) }),
		)
	)

	token, err := a.Authenticate(suite.newCtx(), suite.newSource())
	suite.Require().ErrorIs(err, expectedErr)
	suite.Nil(token)

	suite.Require().Len(events, 1)
	suite.Nil(events[0].Token)
	suite.Equal(suite.newToken(), events[0].InvalidToken)
	suite.Require().ErrorIs(events[0].Err, expectedErr)

	// a rejected token is not validated
	validator.AssertExpectations(suite.T())
}

// TestDetailedSuccess verifies a DetailedTokenParser's token is the Token when
// there is no error, and there is no InvalidToken.
func (suite *AuthenticatorTestSuite) TestDetailedSuccess() {
	var (
		events []AuthenticateEvent[string]
		a      = suite.newAuthenticator(
			WithTokenParsers[string](detailedParser{suite: suite, token: suite.newToken()}),
			WithAuthenticateListenerFuncs(func(e AuthenticateEvent[string]) { events = append(events, e) }),
		)
	)

	token, err := a.Authenticate(suite.newCtx(), suite.newSource())
	suite.Require().NoError(err)
	suite.Equal(suite.newToken(), token)

	suite.Require().Len(events, 1)
	suite.Equal(suite.newToken(), events[0].Token)
	suite.Nil(events[0].InvalidToken)
}

// TestPlainParserTokenWithError verifies a parser that is not a
// DetailedTokenParser is treated as it always was: whatever it returns with an
// error is the Token, and there is no InvalidToken.
func (suite *AuthenticatorTestSuite) TestPlainParserTokenWithError() {
	var (
		expectedErr = errors.New("expected")
		events      []AuthenticateEvent[string]
		a           = suite.newAuthenticator(
			WithTokenParsers(AsTokenParser[string](func(string) (Token, error) {
				return suite.newToken(), expectedErr
			})),
			WithAuthenticateListenerFuncs(func(e AuthenticateEvent[string]) { events = append(events, e) }),
		)
	)

	_, err := a.Authenticate(suite.newCtx(), suite.newSource())
	suite.Require().ErrorIs(err, expectedErr)

	suite.Require().Len(events, 1)
	suite.Equal(suite.newToken(), events[0].Token)
	suite.Nil(events[0].InvalidToken)
}

func TestAuthenticator(t *testing.T) {
	suite.Run(t, new(AuthenticatorTestSuite))
}
