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
	suite.NoError(err)

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
	suite.ErrorIs(err, expectedErr)

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
	suite.ErrorIs(err, expectedErr)

	parser.AssertExpectations(suite.T())
	validator.AssertExpectations(suite.T())
	listener.AssertExpectations(suite.T())
}

func TestAuthenticator(t *testing.T) {
	suite.Run(t, new(AuthenticatorTestSuite))
}
