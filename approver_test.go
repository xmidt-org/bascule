// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ApproversTestSuite struct {
	TestSuite
}

func (suite *ApproversTestSuite) TestAuthorize() {
	const placeholderResource = "placeholder resource"
	approveErr := errors.New("expected Authorize error")

	testCases := []struct {
		name        string
		results     []error
		expectedErr error
	}{
		{
			name:    "EmptyApprovers",
			results: nil,
		},
		{
			name:    "OneSuccess",
			results: []error{nil},
		},
		{
			name:        "OneFailure",
			results:     []error{approveErr},
			expectedErr: approveErr,
		},
		{
			name:        "FirstFailure",
			results:     []error{approveErr, errors.New("should not be called")},
			expectedErr: approveErr,
		},
		{
			name:        "MiddleFailure",
			results:     []error{nil, approveErr, errors.New("should not be called")},
			expectedErr: approveErr,
		},
		{
			name:    "AllSuccess",
			results: []error{nil, nil, nil},
		},
	}

	suite.Run("Append", func() {
		for _, testCase := range testCases {
			suite.Run(testCase.name, func() {
				var (
					testCtx   = suite.testContext()
					testToken = suite.testToken()
					as        Approvers[string]
				)

				for _, err := range testCase.results {
					err := err
					as = as.Append(
						ApproverFunc[string](func(ctx context.Context, resource string, token Token) error {
							suite.Same(testCtx, ctx)
							suite.Equal(testToken, token)
							suite.Equal(placeholderResource, resource)
							return err
						}),
					)
				}

				suite.Equal(
					testCase.expectedErr,
					as.Approve(testCtx, placeholderResource, testToken),
				)
			})
		}
	})

	suite.Run("AppendFunc", func() {
		for _, testCase := range testCases {
			suite.Run(testCase.name, func() {
				var (
					testCtx   = suite.testContext()
					testToken = suite.testToken()
					as        Approvers[string]
				)

				for _, err := range testCase.results {
					err := err
					as = as.AppendFunc(
						func(ctx context.Context, resource string, token Token) error {
							suite.Same(testCtx, ctx)
							suite.Equal(testToken, token)
							suite.Equal(placeholderResource, resource)
							return err
						},
					)
				}

				suite.Equal(
					testCase.expectedErr,
					as.Approve(testCtx, placeholderResource, testToken),
				)
			})
		}
	})
}

func (suite *ApproversTestSuite) TestAny() {
	const placeholderResource = "placeholder resource"
	approveErr := errors.New("expected Authorize error")

	testCases := []struct {
		name        string
		results     []error
		expectedErr error
	}{
		{
			name:    "EmptyApprovers",
			results: nil,
		},
		{
			name:    "OneSuccess",
			results: []error{nil, errors.New("should not be called")},
		},
		{
			name:        "OnlyFailure",
			results:     []error{approveErr},
			expectedErr: approveErr,
		},
		{
			name:    "FirstFailure",
			results: []error{approveErr, nil},
		},
		{
			name:    "LastSuccess",
			results: []error{approveErr, approveErr, nil},
		},
	}

	for _, testCase := range testCases {
		suite.Run(testCase.name, func() {
			var (
				testCtx   = suite.testContext()
				testToken = suite.testToken()
				as        Approvers[string]
			)

			for _, err := range testCase.results {
				err := err
				as = as.Append(
					ApproverFunc[string](func(ctx context.Context, resource string, token Token) error {
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
				anyAs.Approve(testCtx, placeholderResource, testToken),
			)

			if len(as) > 0 {
				// the any instance should be distinct
				as[0] = ApproverFunc[string](
					func(context.Context, string, Token) error {
						suite.Fail("should not have been called")
						return nil
					},
				)

				suite.Equal(
					testCase.expectedErr,
					anyAs.Approve(testCtx, placeholderResource, testToken),
				)
			}
		})
	}
}

func TestApprovers(t *testing.T) {
	suite.Run(t, new(ApproversTestSuite))
}
