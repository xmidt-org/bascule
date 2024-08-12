// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"net/http"

	"github.com/stretchr/testify/suite"
)

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

func (suite *TestSuite) testToken() Token {
	return testToken("test")
}

func (suite *TestSuite) contexter(ctx context.Context) Contexter {
	return new(http.Request).WithContext(ctx)
}
