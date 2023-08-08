// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var attrs = NewAttributes(map[string]interface{}{"testkey": "testval", "attr": 5})

func TestToken(t *testing.T) {
	assert := assert.New(t)
	tokenType := "test type"
	principal := "test principal"
	token := NewToken(tokenType, principal, attrs)
	assert.Equal(tokenType, token.Type())
	assert.Equal(principal, token.Principal())
	assert.Equal(attrs, token.Attributes())
}
