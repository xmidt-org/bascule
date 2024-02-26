package bascule

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ContextTestSuite struct {
	suite.Suite
}

func (suite *ContextTestSuite) testCredentials() Credentials {
	return Credentials{
		Scheme: Scheme("Test"),
		Value:  "test",
	}
}

func (suite *ContextTestSuite) contexter(ctx context.Context) Contexter {
	return new(http.Request).WithContext(ctx)
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

func TestContext(t *testing.T) {
	suite.Run(t, new(ContextTestSuite))
}
