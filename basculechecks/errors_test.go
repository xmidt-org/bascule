// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorWithReason(t *testing.T) {
	assert := assert.New(t)
	testErr := errors.New("test err")
	e := errWithReason{
		err:    testErr,
		reason: "who knows",
	}
	var r Reasoner = e
	assert.Equal("who knows", r.Reason())

	var ee error = e
	assert.Equal("test err", ee.Error())

	assert.Equal(testErr, e.Unwrap())
}
