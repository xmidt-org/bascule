package bascule

import (
	"context"
	"net/http"

	"github.com/stretchr/testify/suite"
)

type testToken struct {
	principal string
}

func (tt *testToken) Principal() string {
	return tt.principal
}

// TestSuite holds generally useful functionality for testing bascule.
type TestSuite struct {
	suite.Suite
}

func (suite *TestSuite) testContext() context.Context {
	return context.WithValue(
		context.Background(),
		struct{}{},
		"test value",
	)
}

func (suite *TestSuite) testCredentials() Credentials {
	return Credentials{
		Scheme: Scheme("Test"),
		Value:  "test",
	}
}

func (suite *TestSuite) testToken() Token {
	return &testToken{
		principal: "test",
	}
}

func (suite *TestSuite) contexter(ctx context.Context) Contexter {
	return new(http.Request).WithContext(ctx)
}
