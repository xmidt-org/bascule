// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule/v1"
)

type CredentialsTestSuite struct {
	suite.Suite
}

func (suite *CredentialsTestSuite) newDefaultSource(value string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(DefaultAuthorizationHeader, value)
	return r
}

func (suite *CredentialsTestSuite) testDefaultCredentialsParserSuccess() {
	const (
		expectedScheme bascule.Scheme = "Test"
		expectedValue  string         = "credentialValue"
	)

	testCases := []string{
		"Test credentialValue",
	}

	for _, testCase := range testCases {
		suite.Run(testCase, func() {
			dp := DefaultCredentialsParser{}
			suite.Require().NotNil(dp)

			creds, err := dp.Parse(context.Background(), suite.newDefaultSource(testCase))
			suite.Require().NoError(err)
			suite.Equal(
				bascule.Credentials{
					Scheme: expectedScheme,
					Value:  expectedValue,
				},
				creds,
			)
		})
	}
}

func (suite *CredentialsTestSuite) testDefaultCredentialsParserFailure() {
	testCases := []string{
		"",
		"  ",
		"thisisnotvalid",
		"Test\tcredentialValue",
		" Test credentialValue",
		"Test credentialValue ",
		"Test  credentialValue",
	}

	for _, testCase := range testCases {
		suite.Run(testCase, func() {
			dp := DefaultCredentialsParser{}
			suite.Require().NotNil(dp)

			creds, err := dp.Parse(context.Background(), suite.newDefaultSource(testCase))
			suite.Require().Error(err)
			suite.Equal(bascule.Credentials{}, creds)

			var ice *bascule.BadCredentialsError
			if suite.ErrorAs(err, &ice) {
				suite.Equal(testCase, ice.Raw)
			}
		})
	}
}

func (suite *CredentialsTestSuite) TestDefaultCredentialsParser() {
	suite.Run("Success", suite.testDefaultCredentialsParserSuccess)
	suite.Run("Failure", suite.testDefaultCredentialsParserFailure)
}

func TestCredentials(t *testing.T) {
	suite.Run(t, new(CredentialsTestSuite))
}
