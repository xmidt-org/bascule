// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PasswordTestSuite struct {
	suite.Suite
}

func (suite *PasswordTestSuite) TestGetPassword() {
	suite.Run("NoPassword", func() {
		token := new(mockToken)
		password, exists := GetPassword(token)

		suite.Empty(password)
		suite.False(exists)
		token.AssertExpectations(suite.T())
	})

	suite.Run("WithPassword", func() {
		const expectedPassword = "this is an expected password" //nolint:gosec
		token := new(mockTokenWithPassword)
		token.ExpectPassword(expectedPassword)

		password, exists := GetPassword(token)
		suite.Equal(expectedPassword, password)
		suite.True(exists)
		token.AssertExpectations(suite.T())
	})
}

func TestPassword(t *testing.T) {
	suite.Run(t, new(PasswordTestSuite))
}
