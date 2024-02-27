package bascule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ContextTestSuite struct {
	TestSuite
}

func (suite *ContextTestSuite) testGetCredentialsSuccess() {
	ctx := context.WithValue(
		context.Background(),
		credentialsContextKey{},
		suite.testCredentials(),
	)

	creds, ok := GetCredentials(ctx)
	suite.Require().True(ok)
	suite.Equal(
		suite.testCredentials(),
		creds,
	)
}

func (suite *ContextTestSuite) testGetCredentialsMissing() {
	creds, ok := GetCredentials(context.Background())
	suite.Equal(Credentials{}, creds)
	suite.False(ok)
}

func (suite *ContextTestSuite) testGetCredentialsWrongType() {
	ctx := context.WithValue(context.Background(), credentialsContextKey{}, 123)
	creds, ok := GetCredentials(ctx)
	suite.Equal(Credentials{}, creds)
	suite.False(ok)
}

func (suite *ContextTestSuite) TestGetCredentials() {
	suite.Run("Success", suite.testGetCredentialsSuccess)
	suite.Run("Missing", suite.testGetCredentialsMissing)
	suite.Run("WrongType", suite.testGetCredentialsWrongType)
}

func (suite *ContextTestSuite) testGetCredentialsFromSuccess() {
	c := suite.contexter(
		context.WithValue(
			context.Background(),
			credentialsContextKey{},
			suite.testCredentials(),
		),
	)

	creds, ok := GetCredentialsFrom(c)
	suite.Require().True(ok)
	suite.Equal(
		suite.testCredentials(),
		creds,
	)
}

func (suite *ContextTestSuite) testGetCredentialsFromMissing() {
	creds, ok := GetCredentialsFrom(
		suite.contexter(context.Background()),
	)

	suite.Equal(Credentials{}, creds)
	suite.False(ok)
}

func (suite *ContextTestSuite) testGetCredentialsFromWrongType() {
	c := suite.contexter(
		context.WithValue(context.Background(), credentialsContextKey{}, 123),
	)

	creds, ok := GetCredentialsFrom(c)
	suite.Equal(Credentials{}, creds)
	suite.False(ok)
}

func (suite *ContextTestSuite) TestGetCredentialsFrom() {
	suite.Run("Success", suite.testGetCredentialsFromSuccess)
	suite.Run("Missing", suite.testGetCredentialsFromMissing)
	suite.Run("WrongType", suite.testGetCredentialsFromWrongType)
}

func (suite *ContextTestSuite) testWithCredentialsSuccess() {
}

func (suite *ContextTestSuite) TestWithCredentials() {
	ctx := WithCredentials(context.Background(), suite.testCredentials())

	creds, ok := ctx.Value(credentialsContextKey{}).(Credentials)
	suite.Require().True(ok)
	suite.Equal(suite.testCredentials(), creds)
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
