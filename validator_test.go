// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ValidatorsTestSuite struct {
	TestSuite

	expectedCtx    context.Context
	expectedSource int
	inputToken     Token
	outputToken    Token
	expectedErr    error
}

func (suite *ValidatorsTestSuite) SetupSuite() {
	suite.expectedCtx = suite.testContext()
	suite.expectedSource = 123
	suite.inputToken = testToken("input token")
	suite.outputToken = testToken("output token")
	suite.expectedErr = errors.New("expected validator error")
}

// assertNoTransform verifies that the validator returns the same token as the input token.
func (suite *ValidatorsTestSuite) assertNoTransform(v Validator[int]) {
	suite.Require().NotNil(v)
	actualToken, actualErr := v.Validate(suite.expectedCtx, suite.expectedSource, suite.inputToken)
	suite.Equal(suite.inputToken, actualToken)
	suite.ErrorIs(suite.expectedErr, actualErr)
}

// assertTransform verifies a validator that returns a different token than the input token.
func (suite *ValidatorsTestSuite) assertTransform(v Validator[int]) {
	suite.Require().NotNil(v)
	actualToken, actualErr := v.Validate(suite.expectedCtx, suite.expectedSource, suite.inputToken)
	suite.Equal(suite.outputToken, actualToken)
	suite.ErrorIs(suite.expectedErr, actualErr)
}

// validateToken is a ValidatorFunc of the signature func(Token) error
func (suite *ValidatorsTestSuite) validateToken(actualToken Token) error {
	suite.Equal(suite.inputToken, actualToken)
	return suite.expectedErr
}

// validateSourceToken is a ValidatorFunc of the signature func(<source>, Token) error
func (suite *ValidatorsTestSuite) validateSourceToken(actualSource int, actualToken Token) error {
	suite.Equal(suite.expectedSource, actualSource)
	suite.Equal(suite.inputToken, actualToken)
	return suite.expectedErr
}

// validateContextToken is a ValidatorFunc of the signature func(context.Context, Token) error
func (suite *ValidatorsTestSuite) validateContextToken(actualCtx context.Context, actualToken Token) error {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.inputToken, actualToken)
	return suite.expectedErr
}

// validateContextSourceToken is a ValidatorFunc of the signature func(context.Context, <source>, Token) error
func (suite *ValidatorsTestSuite) validateContextSourceToken(actualCtx context.Context, actualSource int, actualToken Token) error {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.expectedSource, actualSource)
	suite.Equal(suite.inputToken, actualToken)
	return suite.expectedErr
}

// transformToken is a ValidatorFunc of the signature func(Token) (Token, error).
// This variant returns suite.outputToken.
func (suite *ValidatorsTestSuite) transformToken(actualToken Token) (Token, error) {
	suite.Equal(suite.inputToken, actualToken)
	return suite.outputToken, suite.expectedErr
}

// transformTokenToNil is a ValidatorFunc of the signature func(Token) (Token, error).
// This variant returns a nil Token, indicating that the original token is unchanged.
func (suite *ValidatorsTestSuite) transformTokenToNil(actualToken Token) (Token, error) {
	suite.Equal(suite.inputToken, actualToken)
	return nil, suite.expectedErr
}

// transformSourceToken is a ValidatorFunc of the signature func(<source>, Token) (Token, error)
// This variant returns suite.outputToken.
func (suite *ValidatorsTestSuite) transformSourceToken(actualSource int, actualToken Token) (Token, error) {
	suite.Equal(suite.expectedSource, actualSource)
	suite.Equal(suite.inputToken, actualToken)
	return suite.outputToken, suite.expectedErr
}

// transformSourceTokenToNil is a ValidatorFunc of the signature func(<source>, Token) (Token, error)
// This variant returns a nil Token, indicating that the original token is unchanged.
func (suite *ValidatorsTestSuite) transformSourceTokenToNil(actualSource int, actualToken Token) (Token, error) {
	suite.Equal(suite.expectedSource, actualSource)
	suite.Equal(suite.inputToken, actualToken)
	return nil, suite.expectedErr
}

// transformContextToken is a ValidatorFunc of the signature func(context.context, Token) (Token, error)
// This variant returns suite.outputToken.
func (suite *ValidatorsTestSuite) transformContextToken(actualCtx context.Context, actualToken Token) (Token, error) {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.inputToken, actualToken)
	return suite.outputToken, suite.expectedErr
}

// transformContextTokenToNil is a ValidatorFunc of the signature func(context.context, Token) (Token, error)
// This variant returns a nil Token, indicating that the original token is unchanged.
func (suite *ValidatorsTestSuite) transformContextTokenToNil(actualCtx context.Context, actualToken Token) (Token, error) {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.inputToken, actualToken)
	return nil, suite.expectedErr
}

// transformContextSourceToken is a ValidatorFunc of the signature func(context.Context, <source>, Token) (Token, error)
// This variant returns suite.outputToken.
func (suite *ValidatorsTestSuite) transformContextSourceToken(actualCtx context.Context, actualSource int, actualToken Token) (Token, error) {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.expectedSource, actualSource)
	suite.Equal(suite.inputToken, actualToken)
	return suite.outputToken, suite.expectedErr
}

// transformContextSourceToken is a ValidatorFunc of the signature func(context.Context, <source>, Token) (Token, error)
// This variant returns a nil Token, indicating that the original token is unchanged.
func (suite *ValidatorsTestSuite) transformContextSourceTokenToNil(actualCtx context.Context, actualSource int, actualToken Token) (Token, error) {
	suite.Equal(suite.expectedCtx, actualCtx)
	suite.Equal(suite.expectedSource, actualSource)
	suite.Equal(suite.inputToken, actualToken)
	return nil, suite.expectedErr
}

func (suite *ValidatorsTestSuite) testAsValidatorToken() {
	suite.Run("ReturnError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.validateToken)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(Token) error
			f := Custom(suite.validateToken)
			v := AsValidator[int](f)
			suite.assertNoTransform(v)
		})
	})

	suite.Run("ReturnTokenError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.transformToken)
			suite.assertTransform(v)
		})

		suite.Run("NilOutputToken", func() {
			v := AsValidator[int](suite.transformTokenToNil)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(Token) (Token, error)
			f := Custom(suite.transformToken)
			v := AsValidator[int](f)
			suite.assertTransform(v)
		})
	})
}

func (suite *ValidatorsTestSuite) testAsValidatorSourceToken() {
	suite.Run("ReturnError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.validateSourceToken)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(int, Token) error
			f := Custom(suite.validateSourceToken)
			v := AsValidator[int](f)
			suite.assertNoTransform(v)
		})
	})

	suite.Run("ReturnTokenError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.transformSourceToken)
			suite.assertTransform(v)
		})

		suite.Run("NilOutputToken", func() {
			v := AsValidator[int](suite.transformSourceTokenToNil)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(int, Token) (Token, error)
			f := Custom(suite.transformSourceToken)
			v := AsValidator[int](f)
			suite.assertTransform(v)
		})
	})
}

func (suite *ValidatorsTestSuite) testAsValidatorContextToken() {
	suite.Run("ReturnError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.validateContextToken)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(context.Context, Token) error
			f := Custom(suite.validateContextToken)
			v := AsValidator[int](f)
			suite.assertNoTransform(v)
		})
	})

	suite.Run("ReturnTokenError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.transformContextToken)
			suite.assertTransform(v)
		})

		suite.Run("NilOutputToken", func() {
			v := AsValidator[int](suite.transformContextTokenToNil)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(context.Context, Token) (Token, error)
			f := Custom(suite.transformContextToken)
			v := AsValidator[int](f)
			suite.assertTransform(v)
		})
	})
}

func (suite *ValidatorsTestSuite) testAsValidatorContextSourceToken() {
	suite.Run("ReturnError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.validateContextSourceToken)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(context.Context, int, Token) error
			f := Custom(suite.validateContextSourceToken)
			v := AsValidator[int](f)
			suite.assertNoTransform(v)
		})
	})

	suite.Run("ReturnTokenError", func() {
		suite.Run("Simple", func() {
			v := AsValidator[int](suite.transformContextSourceToken)
			suite.assertTransform(v)
		})

		suite.Run("NilOutputToken", func() {
			v := AsValidator[int](suite.transformContextSourceTokenToNil)
			suite.assertNoTransform(v)
		})

		suite.Run("CustomType", func() {
			type Custom func(context.Context, int, Token) (Token, error)
			f := Custom(suite.transformContextSourceToken)
			v := AsValidator[int](f)
			suite.assertTransform(v)
		})
	})
}

func (suite *ValidatorsTestSuite) TestAsValidator() {
	suite.Run("Token", suite.testAsValidatorToken)
	suite.Run("SourceToken", suite.testAsValidatorSourceToken)
	suite.Run("ContextToken", suite.testAsValidatorContextToken)
	suite.Run("ContextSourceToken", suite.testAsValidatorContextSourceToken)
}

// newValidators constructs an array of validators that can only be called once
// and which successfully validate the suite's input token.
func (suite *ValidatorsTestSuite) newValidators(count int) (vs []Validator[int]) {
	vs = make([]Validator[int], 0, count)
	for len(vs) < cap(vs) {
		v := new(mockValidator[int])
		v.ExpectValidate(suite.expectedCtx, suite.expectedSource, suite.inputToken).
			Return(nil, nil).Once()

		vs = append(vs, v)
	}

	return
}

func (suite *ValidatorsTestSuite) TestValidate() {
	suite.Run("NoValidators", func() {
		outputToken, err := Validate[int](suite.expectedCtx, suite.expectedSource, suite.inputToken)
		suite.Equal(suite.inputToken, outputToken)
		suite.NoError(err)
	})

	suite.Run("NilOutputToken", func() {
		for _, count := range []int{1, 2, 5} {
			suite.Run(fmt.Sprintf("count=%d", count), func() {
				vs := suite.newValidators(count)
				actualToken, actualErr := Validate(suite.expectedCtx, suite.expectedSource, suite.inputToken, vs...)
				suite.Equal(suite.inputToken, actualToken)
				suite.NoError(actualErr)
				assertValidators(suite.T(), vs...)
			})
		}
	})
}

func (suite *ValidatorsTestSuite) TestCompositeValidators() {
	suite.Run("Empty", func() {
		var vs Validators[int]
		outputToken, err := vs.Validate(suite.expectedCtx, suite.expectedSource, suite.inputToken)
		suite.Equal(suite.inputToken, outputToken)
		suite.NoError(err)
	})

	suite.Run("NotEmpty", func() {
		suite.Run("len=1", func() {
			v := new(mockValidator[int])
			v.ExpectValidate(suite.expectedCtx, suite.expectedSource, suite.inputToken).
				Return(suite.outputToken, nil).Once()

			var vs Validators[int]
			vs = vs.Append(v)
			actualToken, actualErr := vs.Validate(suite.expectedCtx, suite.expectedSource, suite.inputToken)
			suite.Equal(suite.outputToken, actualToken)
			suite.NoError(actualErr)
			assertValidators(suite.T(), v)
		})

		suite.Run("len=2", func() {
			v1 := new(mockValidator[int])
			v1.ExpectValidate(suite.expectedCtx, suite.expectedSource, suite.inputToken).
				Return(nil, nil).Once()

			v2 := new(mockValidator[int])
			v2.ExpectValidate(suite.expectedCtx, suite.expectedSource, suite.inputToken).
				Return(nil, nil).Once()

			var vs Validators[int]
			vs = vs.Append(v1, v2)
			actualToken, actualErr := vs.Validate(suite.expectedCtx, suite.expectedSource, suite.inputToken)
			suite.Equal(suite.inputToken, actualToken) // the token should be unchanged
			suite.NoError(actualErr)
			assertValidators(suite.T(), v1, v2)
		})
	})
}

func TestValidators(t *testing.T) {
	suite.Run(t, new(ValidatorsTestSuite))
}
