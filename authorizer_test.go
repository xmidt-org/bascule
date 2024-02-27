package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthorizersTestSuite struct {
	suite.Suite
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
			testCtx := context.WithValue(
				context.Background(),
				struct{}{},
				"value",
			)

			var testToken Token = &testToken{
				principal: "test",
			}

			var as Authorizers[string]
			for _, err := range testCase.results {
				err := err
				as.Add(
					AuthorizerFunc[string](func(ctx context.Context, token Token, resource string) error {
						suite.Same(testCtx, ctx)
						suite.Same(testToken, token)
						suite.Equal(placeholderResource, resource)
						return err
					}),
				)
			}

			suite.Equal(
				testCase.expectedErr,
				as.Authorize(testCtx, testToken, placeholderResource),
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
			testCtx := context.WithValue(
				context.Background(),
				struct{}{},
				"value",
			)

			var testToken Token = &testToken{
				principal: "test",
			}

			var as Authorizers[string]
			for _, err := range testCase.results {
				err := err
				as.Add(
					AuthorizerFunc[string](func(ctx context.Context, token Token, resource string) error {
						suite.Same(testCtx, ctx)
						suite.Same(testToken, token)
						suite.Equal(placeholderResource, resource)
						return err
					}),
				)
			}

			anyAs := as.Any()
			suite.Equal(
				testCase.expectedErr,
				anyAs.Authorize(testCtx, testToken, placeholderResource),
			)

			if len(as) > 0 {
				// the any instance should be distinct
				as[0] = AuthorizerFunc[string](
					func(context.Context, Token, string) error {
						suite.Fail("should not have been called")
						return nil
					},
				)

				suite.Equal(
					testCase.expectedErr,
					anyAs.Authorize(testCtx, testToken, placeholderResource),
				)
			}
		})
	}
}

func TestAuthorizers(t *testing.T) {
	suite.Run(t, new(AuthorizersTestSuite))
}
