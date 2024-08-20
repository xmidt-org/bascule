// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type testToken struct {
	principal    string
	capabilities []string
}

func (tt *testToken) Principal() string {
	return tt.principal
}

func (tt *testToken) Capabilities() []string {
	return tt.capabilities
}

type ApproverTestSuite struct {
	suite.Suite
}

// newRequest creates an HTTP request with an empty body, since these
// tests do not need to use any entity bodies.
func (suite *ApproverTestSuite) newRequest(method, url string) *http.Request {
	return httptest.NewRequest(method, url, nil)
}

// newToken creates a stub token that has the given capabilities.
func (suite *ApproverTestSuite) newToken(capabilities ...string) bascule.Token {
	return &testToken{
		principal:    "test",
		capabilities: append([]string{}, capabilities...),
	}
}

// newApprover creates a Approver from a set of options that
// must be valid.
func (suite *ApproverTestSuite) newApprover(opts ...ApproverOption) *Approver {
	ca, err := NewApprover(opts...)
	suite.Require().NoError(err)
	suite.Require().NotNil(ca)
	return ca
}

func (suite *ApproverTestSuite) TestInvalidPrefix() {
	invalidPrefixes := []string{
		"(.*):foo:", // subexpressions aren't allowed
		"(?!foo)",
	}

	for i, invalid := range invalidPrefixes {
		suite.Run(strconv.Itoa(i), func() {
			ca, err := NewApprover(
				WithPrefixes(invalid),
			)

			suite.Error(err)
			suite.Nil(ca)
		})
	}
}

func (suite *ApproverTestSuite) TestInvalidAllMethod() {
	ca, err := NewApprover(
		WithAllMethod(""), // blanks aren't allowed
	)

	suite.Error(err)
	suite.Nil(ca)
}

func (suite *ApproverTestSuite) testApproveMissingCapabilities() {
	ca := suite.newApprover() // don't need any options for this case
	err := ca.Approve(context.Background(), suite.newRequest("GET", "/test"), new(testToken))
	suite.ErrorIs(err, bascule.ErrUnauthorized)
}

func (suite *ApproverTestSuite) testApproveSuccess() {
	testCases := []struct {
		capabilities []string
		request      *http.Request
		options      []ApproverOption
	}{
		{
			capabilities: []string{"x1:webpa:api:.*:all"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:device/.*/config:all"},
			request:      suite.newRequest("GET", "/device/DEADBEEF/config"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:/test/.*:put"},
			request:      suite.newRequest("PUT", "/test/foo"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{
				"x1:xmidt:api:/device/.*/config:all",
				"x1:webpa:api:/something/else:get",
				"x1:doesnot:apply:.*:all",
				"x1:webpa:api:/test/.*:put", // this should match
			},
			request: suite.newRequest("PUT", "/test/foo"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:/test/.*:custom"},
			request:      suite.newRequest("PATCH", "/test/foo"),
			options: []ApproverOption{
				WithPrefixes("x1:xmidt:api:", "x1:webpa:api:"),
				WithAllMethod("custom"),
			},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var (
				token = suite.newToken(testCase.capabilities...)
				ca    = suite.newApprover(testCase.options...)
			)

			suite.NoError(
				ca.Approve(context.Background(), testCase.request, token),
			)
		})
	}
}

func (suite *ApproverTestSuite) testApproveUnauthorized() {
	testCases := []struct {
		capabilities []string
		request      *http.Request
		options      []ApproverOption
	}{
		{
			capabilities: []string{"x1:xmidt:api:.*:all"},
			request:      suite.newRequest("GET", "/"),
			options:      nil, // will reject all tokens
		},
		{
			capabilities: []string{"x1:webpa:api:.*:put"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:/doesnotmatch:get"},
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
		{
			capabilities: []string{"x1:webpa:api:(?!foo):put"}, // bad expression
			request:      suite.newRequest("GET", "/test"),
			options: []ApproverOption{
				WithPrefixes("x1:webpa:api:"),
			},
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var (
				token = suite.newToken(testCase.capabilities...)
				ca    = suite.newApprover(testCase.options...)
			)

			err := ca.Approve(context.Background(), testCase.request, token)
			suite.ErrorIs(err, bascule.ErrUnauthorized)
		})
	}
}

func (suite *ApproverTestSuite) TestApprove() {
	suite.Run("MissingCapabilities", suite.testApproveMissingCapabilities)
	suite.Run("Success", suite.testApproveSuccess)
	suite.Run("Unauthorized", suite.testApproveUnauthorized)
}

func TestApprover(t *testing.T) {
	suite.Run(t, new(ApproverTestSuite))
}
