// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidators(t *testing.T) {
	emptyAttributes := NewAttributes(map[string]interface{}{})
	testErr := errors.New("test err")
	var (
		failFunc ValidatorFunc = func(_ context.Context, _ Token) error {
			return testErr
		}
		successFunc ValidatorFunc = func(_ context.Context, _ Token) error {
			return nil
		}
	)
	assert := assert.New(t)
	validatorF := Validators([]Validator{successFunc, failFunc})
	validatorS := Validators([]Validator{successFunc, successFunc, successFunc})
	err := validatorS.Check(context.Background(), NewToken("type", "principal", emptyAttributes))
	assert.NoError(err)
	errs := validatorF.Check(context.Background(), NewToken("", "", emptyAttributes))
	assert.NotNil(errs)
	assert.True(errors.As(errs, &Errors{}))
}
