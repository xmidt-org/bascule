// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthorizerTestSuite struct {
	suite.Suite
}

// newAuthorizer creates an Authorizer under test, asserting
// that no errors occurred.
func (suite *AuthorizerTestSuite) newAuthorizer(opts ...AuthorizerOption[string]) *Authorizer[string] {
	a, err := NewAuthorizer(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(a)
	return a
}

func (suite *AuthorizerTestSuite) newToken() Token {
	return StubToken("test")
}

func (suite *AuthorizerTestSuite) newCtx() context.Context {
	type testContextKey struct{}
	return context.WithValue(
		context.Background(),
		testContextKey{},
		"test value",
	)
}

func (suite *AuthorizerTestSuite) newResource() string {
	return "test resource"
}

func (suite *AuthorizerTestSuite) TestNoOptions() {
	a := suite.newAuthorizer()

	err := a.Authorize(
		suite.newCtx(),
		suite.newResource(),
		suite.newToken(),
	)

	suite.NoError(err)
}

func (suite *AuthorizerTestSuite) TestFullSuccess() {
	var (
		expectedCtx      = suite.newCtx()
		expectedResource = suite.newResource()
		expectedToken    = suite.newToken()

		approver1 = new(mockApprover[string])
		approver2 = new(mockApprover[string])

		listener1 = new(mockAuthorizeListener[string])
		listener2 = new(mockAuthorizeListener[string])

		a = suite.newAuthorizer(
			WithApprovers(approver1, approver2),
			WithAuthorizeListeners(listener1),
			WithAuthorizeListenerFuncs(listener2.OnEvent),
		)
	)

	approver1.ExpectApprove(expectedCtx, expectedResource, expectedToken).
		Return(nil).Once()
	approver2.ExpectApprove(expectedCtx, expectedResource, expectedToken).
		Return(nil).Once()

	listener1.ExpectOnEvent(AuthorizeEvent[string]{
		Resource: expectedResource,
		Token:    expectedToken,
		Err:      nil,
	})

	listener2.ExpectOnEvent(AuthorizeEvent[string]{
		Resource: expectedResource,
		Token:    expectedToken,
		Err:      nil,
	})

	err := a.Authorize(expectedCtx, expectedResource, expectedToken)
	suite.NoError(err)

	listener1.AssertExpectations(suite.T())
	listener2.AssertExpectations(suite.T())
	approver1.AssertExpectations(suite.T())
	approver2.AssertExpectations(suite.T())
}

func (suite *AuthorizerTestSuite) TestFullFirstApproverFail() {
	var (
		expectedCtx      = suite.newCtx()
		expectedResource = suite.newResource()
		expectedToken    = suite.newToken()
		expectedErr      = errors.New("expected")

		approver1 = new(mockApprover[string])
		approver2 = new(mockApprover[string])

		listener = new(mockAuthorizeListener[string])

		a = suite.newAuthorizer(
			WithApprovers(approver1, approver2),
			WithAuthorizeListeners(listener),
		)
	)

	approver1.ExpectApprove(expectedCtx, expectedResource, expectedToken).
		Return(expectedErr).Once()

	listener.ExpectOnEvent(AuthorizeEvent[string]{
		Resource: expectedResource,
		Token:    expectedToken,
		Err:      expectedErr,
	})

	err := a.Authorize(expectedCtx, expectedResource, expectedToken)
	suite.ErrorIs(err, expectedErr)

	listener.AssertExpectations(suite.T())
	approver1.AssertExpectations(suite.T())
	approver2.AssertExpectations(suite.T())
}

func (suite *AuthorizerTestSuite) TestFullSecondApproverFail() {
	var (
		expectedCtx      = suite.newCtx()
		expectedResource = suite.newResource()
		expectedToken    = suite.newToken()
		expectedErr      = errors.New("expected")

		approver1 = new(mockApprover[string])
		approver2 = new(mockApprover[string])

		listener = new(mockAuthorizeListener[string])

		a = suite.newAuthorizer(
			WithApprovers(approver1, approver2),
			WithAuthorizeListeners(listener),
		)
	)

	approver1.ExpectApprove(expectedCtx, expectedResource, expectedToken).
		Return(nil).Once()
	approver2.ExpectApprove(expectedCtx, expectedResource, expectedToken).
		Return(expectedErr).Once()

	listener.ExpectOnEvent(AuthorizeEvent[string]{
		Resource: expectedResource,
		Token:    expectedToken,
		Err:      expectedErr,
	})

	err := a.Authorize(expectedCtx, expectedResource, expectedToken)
	suite.ErrorIs(err, expectedErr)

	listener.AssertExpectations(suite.T())
	approver1.AssertExpectations(suite.T())
	approver2.AssertExpectations(suite.T())
}

func TestAuthorizer(t *testing.T) {
	suite.Run(t, new(AuthorizerTestSuite))
}
