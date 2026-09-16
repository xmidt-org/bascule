// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type ErrorsTestSuite struct {
	suite.Suite
}

func (suite *ErrorsTestSuite) newRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

// TestDenials covers which of the two denials a request gets.
func (suite *ErrorsTestSuite) TestDenials() {
	testCases := []struct {
		name         string
		capabilities []string
		method       string
		target       string
		expected     error
	}{
		{
			name:         "NoCapabilities",
			capabilities: nil,
			method:       "GET",
			target:       "/test",
			expected:     ErrNoCapabilities,
		}, {
			// a capability for another service is still a capability
			name:         "OnlyAnotherServicesCapabilities",
			capabilities: []string{"x1:xmidt:api:/test:all"},
			method:       "GET",
			target:       "/test",
			expected:     ErrNoMatchingCapability,
		}, {
			name:         "WrongURL",
			capabilities: []string{"x1:webpa:api:/other:all"},
			method:       "GET",
			target:       "/test",
			expected:     ErrNoMatchingCapability,
		}, {
			name:         "WrongMethod",
			capabilities: []string{"x1:webpa:api:/test:put"},
			method:       "GET",
			target:       "/test",
			expected:     ErrNoMatchingCapability,
		},
	}

	for _, testCase := range testCases {
		suite.Run(testCase.name, func() {
			ca, err := NewApprover(WithPrefixes("x1:webpa:api:"))
			suite.Require().NoError(err)

			err = ca.Approve(
				context.Background(),
				suite.newRequest(testCase.method, testCase.target),
				&testToken{principal: "test", capabilities: testCase.capabilities},
			)

			suite.Require().Error(err)
			suite.ErrorIs(err, testCase.expected)
			suite.ErrorIs(err, bascule.ErrUnauthorized,
				"every denial must still satisfy the general case")
		})
	}
}

// TestDenialsAreDistinct verifies the two errors are not interchangeable, so
// that a caller asking for one is not silently given the other.
func (suite *ErrorsTestSuite) TestDenialsAreDistinct() {
	suite.NotErrorIs(ErrNoCapabilities, ErrNoMatchingCapability)
	suite.NotErrorIs(ErrNoMatchingCapability, ErrNoCapabilities)
}

// TestNoCapabilitiesIsAlsoNoMatch verifies that a token carrying nothing is
// reported as both: every denial is ErrNoMatchingCapability, and this one is
// additionally ErrNoCapabilities.  A caller counting denials broadly should not
// have to know about the narrower case.
func (suite *ErrorsTestSuite) TestNoCapabilitiesIsAlsoNoMatch() {
	ca, err := NewApprover(WithPrefixes("x1:webpa:api:"))
	suite.Require().NoError(err)

	err = ca.Approve(
		context.Background(),
		suite.newRequest("GET", "/test"),
		&testToken{principal: "test"},
	)

	suite.Require().Error(err)
	suite.ErrorIs(err, ErrNoCapabilities)
	suite.ErrorIs(err, ErrNoMatchingCapability)
	suite.ErrorIs(err, bascule.ErrUnauthorized)
}

func (suite *ErrorsTestSuite) TestApproved() {
	ca, err := NewApprover(WithPrefixes("x1:webpa:api:"))
	suite.Require().NoError(err)

	suite.NoError(ca.Approve(
		context.Background(),
		suite.newRequest("GET", "/test"),
		&testToken{principal: "test", capabilities: []string{"x1:webpa:api:/test:all"}},
	))
}

func TestErrors(t *testing.T) {
	suite.Run(t, new(ErrorsTestSuite))
}
