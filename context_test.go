// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ContextTestSuite struct {
	TestSuite
}

func (suite *ContextTestSuite) testGetTokenSuccess() {
	ctx := context.WithValue(
		context.Background(),
		tokenContextKey{},
		suite.testToken(),
	)

	token, ok := GetToken(ctx)
	suite.Require().True(ok)
	suite.Equal(
		suite.testToken(),
		token,
	)
}

func (suite *ContextTestSuite) testGetTokenMissing() {
	token, ok := GetToken(context.Background())
	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) testGetTokenWrongType() {
	ctx := context.WithValue(context.Background(), tokenContextKey{}, 123)
	token, ok := GetToken(ctx)
	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) TestGetToken() {
	suite.Run("Success", suite.testGetTokenSuccess)
	suite.Run("Missing", suite.testGetTokenMissing)
	suite.Run("WrongType", suite.testGetTokenWrongType)
}

func (suite *ContextTestSuite) testGetTokenFromSuccess() {
	c := suite.contexter(
		context.WithValue(
			context.Background(),
			tokenContextKey{},
			suite.testToken(),
		),
	)

	token, ok := GetTokenFrom(c)
	suite.Require().True(ok)
	suite.Equal(
		suite.testToken(),
		token,
	)
}

func (suite *ContextTestSuite) testGetTokenFromMissing() {
	token, ok := GetTokenFrom(
		suite.contexter(context.Background()),
	)

	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) testGetTokenFromWrongType() {
	c := suite.contexter(
		context.WithValue(context.Background(), tokenContextKey{}, 123),
	)

	token, ok := GetTokenFrom(c)
	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) TestGetTokenFrom() {
	suite.Run("Success", suite.testGetTokenFromSuccess)
	suite.Run("Missing", suite.testGetTokenFromMissing)
	suite.Run("WrongType", suite.testGetTokenFromWrongType)
}

func (suite *ContextTestSuite) TestWithToken() {
	ctx := WithToken(context.Background(), suite.testToken())

	token, ok := ctx.Value(tokenContextKey{}).(Token)
	suite.Require().True(ok)
	suite.Equal(suite.testToken(), token)
}

func TestContext(t *testing.T) {
	suite.Run(t, new(ContextTestSuite))
}
