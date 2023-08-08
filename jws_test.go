// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	assert := assert.New(t)
	claims := ClaimsWithLeeway{
		MapClaims: make(jwt.MapClaims),
		Leeway: Leeway{
			EXP: 5,
			NBF: 5,
			IAT: 5,
		},
	}
	err := claims.Valid()
	assert.NoError(err)
}
