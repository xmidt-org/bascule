// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthorizersTestSuite struct {
	TestSuite
}

func (suite *AuthorizersTestSuite) TestAuthorize() {
	const placeholderResource = "placeholder resource"
	authorizeErr := errors.New("expected Authorize error")

	testCases := []struct {
		name        string
		results     []error
		expectedErr error
	}{
		{
			name:    "EmptyAuthorizers",
			results: nil,
		},
		{
			name:    "OneSuccess",
			results: []error{nil},
		},
		{
			name:        "OneFailure",
			results:     []error{authorizeErr},
			expectedErr: authorizeErr,
		},
		{
			name:        "FirstFailure",
			results:     []error{authorizeErr, errors.New("should not be called")},
			expectedErr: authorizeErr,
		},
		{
			name:        "MiddleFailure",
			results:     []error{nil, authorizeErr, errors.New("should not be called")},
			expectedErr: authorizeErr,
		},
		{
			name:    "AllSuccess",
			results: []error{nil, nil, nil},
		},
	}

	for _, testCase := range testCases {
		suite.Run(testCase.name, func() {
			var (
				testCtx   = suite.testContext()
				testToken = suite.testToken()
				as        Authorizers[string]
			)

			for _, err := range testCase.results {
				err := err
				as = as.Append(
					AuthorizerFunc[string](func(ctx context.Context, resource string, token Token) error {
						suite.Same(testCtx, ctx)
						suite.Equal(testToken, token)
						suite.Equal(placeholderResource, resource)
						return err
					}),
				)
			}

			suite.Equal(
				testCase.expectedErr,
				as.Authorize(testCtx, placeholderResource, testToken),
			)
		})
	}
}

func (suite *AuthorizersTestSuite) TestAny() {
	const placeholderResource = "placeholder resource"
	authorizeErr := errors.New("expected Authorize error")

	testCases := []struct {
		name        string
		results     []error
		expectedErr error
	}{
		{
			name:    "EmptyAuthorizers",
			results: nil,
		},
		{
			name:    "OneSuccess",
			results: []error{nil, errors.New("should not be called")},
		},
		{
			name:        "OnlyFailure",
			results:     []error{authorizeErr},
			expectedErr: authorizeErr,
		},
		{
			name:    "FirstFailure",
			results: []error{authorizeErr, nil},
		},
		{
			name:    "LastSuccess",
			results: []error{authorizeErr, authorizeErr, nil},
		},
	}

	for _, testCase := range testCases {
		suite.Run(testCase.name, func() {
			var (
				testCtx   = suite.testContext()
				testToken = suite.testToken()
				as        Authorizers[string]
			)

			for _, err := range testCase.results {
				err := err
				as = as.Append(
					AuthorizerFunc[string](func(ctx context.Context, resource string, token Token) error {
						suite.Same(testCtx, ctx)
						suite.Equal(testToken, token)
						suite.Equal(placeholderResource, resource)
						return err
					}),
				)
			}

			anyAs := as.Any()
			suite.Equal(
				testCase.expectedErr,
				anyAs.Authorize(testCtx, placeholderResource, testToken),
			)

			if len(as) > 0 {
				// the any instance should be distinct
				as[0] = AuthorizerFunc[string](
					func(context.Context, string, Token) error {
						suite.Fail("should not have been called")
						return nil
					},
				)

				suite.Equal(
					testCase.expectedErr,
					anyAs.Authorize(testCtx, placeholderResource, testToken),
				)
			}
		})
	}
}

func TestAuthorizers(t *testing.T) {
	suite.Run(t, new(AuthorizersTestSuite))
}
