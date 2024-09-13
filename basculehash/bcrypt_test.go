// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type BcryptTestSuite struct {
	TestSuite
}

func (suite *BcryptTestSuite) TestHash() {
	suite.Run("DefaultCost", func() {
		suite.goodHash(
			Bcrypt{}.Hash(suite.plaintext),
		)
	})

	suite.Run("CustomCost", func() {
		suite.goodHash(
			Bcrypt{Cost: 12}.Hash(suite.plaintext),
		)
	})

	suite.Run("CostTooHigh", func() {
		suite.badHash(
			Bcrypt{Cost: bcrypt.MaxCost + 100}.Hash(suite.plaintext),
		)
	})
}

func (suite *BcryptTestSuite) TestMatches() {
	suite.Run("Success", func() {
		for _, cost := range []int{0 /* default */, 4, 8} {
			suite.Run(fmt.Sprintf("cost=%d", cost), func() {
				var (
					hasher = Bcrypt{Cost: cost}
					hashed = suite.goodHash(
						hasher.Hash(suite.plaintext),
					)

					ok, err = hasher.Matches(suite.plaintext, hashed)
				)

				suite.True(ok)
				suite.NoError(err)
			})
		}
	})

	suite.Run("Fail", func() {
		for _, cost := range []int{0 /* default */, 4, 8} {
			suite.Run(fmt.Sprintf("cost=%d", cost), func() {
				var (
					hasher = Bcrypt{Cost: cost}
					hashed = suite.goodHash(
						hasher.Hash(suite.plaintext),
					)

					ok, err = hasher.Matches([]byte("a different plaintext"), hashed)
				)

				suite.False(ok)
				suite.Error(err)
			})
		}
	})
}

func TestBcrypt(t *testing.T) {
	suite.Run(t, new(BcryptTestSuite))
}
