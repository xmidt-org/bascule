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

func (suite *ContextTestSuite) testGetSuccess() {
	ctx := context.WithValue(
		context.Background(),
		tokenContextKey{},
		suite.testToken(),
	)

	token, ok := Get(ctx)
	suite.Require().True(ok)
	suite.Equal(
		suite.testToken(),
		token,
	)
}

func (suite *ContextTestSuite) testGetMissing() {
	token, ok := Get(context.Background())
	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) testGetWrongType() {
	ctx := context.WithValue(context.Background(), tokenContextKey{}, 123)
	token, ok := Get(ctx)
	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) TestGet() {
	suite.Run("Success", suite.testGetSuccess)
	suite.Run("Missing", suite.testGetMissing)
	suite.Run("WrongType", suite.testGetWrongType)
}

func (suite *ContextTestSuite) testGetFromSuccess() {
	c := suite.contexter(
		context.WithValue(
			context.Background(),
			tokenContextKey{},
			suite.testToken(),
		),
	)

	token, ok := GetFrom(c)
	suite.Require().True(ok)
	suite.Equal(
		suite.testToken(),
		token,
	)
}

func (suite *ContextTestSuite) testGetFromMissing() {
	token, ok := GetFrom(
		suite.contexter(context.Background()),
	)

	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) testGetFromWrongType() {
	c := suite.contexter(
		context.WithValue(context.Background(), tokenContextKey{}, 123),
	)

	token, ok := GetFrom(c)
	suite.Nil(token)
	suite.False(ok)
}

func (suite *ContextTestSuite) TestGetFrom() {
	suite.Run("Success", suite.testGetFromSuccess)
	suite.Run("Missing", suite.testGetFromMissing)
	suite.Run("WrongType", suite.testGetFromWrongType)
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
