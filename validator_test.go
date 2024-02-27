package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ValidatorsTestSuite struct {
	TestSuite
}

func (suite *ValidatorsTestSuite) TestValidate() {
	validateErr := errors.New("expected Validate error")

	testCases := []struct {
		name        string
		results     []error
		expectedErr error
	}{
		{
			name:    "EmptyValidators",
			results: nil,
		},
		{
			name:    "OneSuccess",
			results: []error{nil},
		},
		{
			name:        "OneFailure",
			results:     []error{validateErr},
			expectedErr: validateErr,
		},
		{
			name:        "FirstFailure",
			results:     []error{validateErr, errors.New("should not be called")},
			expectedErr: validateErr,
		},
		{
			name:        "MiddleFailure",
			results:     []error{nil, validateErr, errors.New("should not be called")},
			expectedErr: validateErr,
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
				vs        Validators
			)

			for _, err := range testCase.results {
				err := err
				vs.Add(
					ValidatorFunc(func(ctx context.Context, token Token) error {
						suite.Same(testCtx, ctx)
						suite.Same(testToken, token)
						return err
					}),
				)
			}

			suite.Equal(
				testCase.expectedErr,
				vs.Validate(testCtx, testToken),
			)
		})
	}
}

func TestValidators(t *testing.T) {
	suite.Run(t, new(ValidatorsTestSuite))
}
