// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

const bcryptPlaintext string = "bcrypt plaintext"

type BcryptTestSuite struct {
	suite.Suite
}

// goodHash returns a hash that is expected to be successful.
// The plaintext() is hashed with the given cost.
func (suite *BcryptTestSuite) goodHash(cost int) []byte {
	var (
		b      bytes.Buffer
		hasher = Bcrypt{Cost: cost}
		_, err = hasher.Hash(&b, []byte(bcryptPlaintext))
	)

	suite.Require().NoError(err)
	return b.Bytes()
}

func (suite *BcryptTestSuite) TestHash() {
	suite.Run("DefaultCost", func() {
		var (
			o      strings.Builder
			hasher = Bcrypt{}

			n, err = hasher.Hash(&o, []byte(bcryptPlaintext))
		)

		suite.NoError(err)
		suite.Equal(o.Len(), n)
	})

	suite.Run("CustomCost", func() {
		var (
			o      strings.Builder
			hasher = Bcrypt{Cost: 12}

			n, err = hasher.Hash(&o, []byte(bcryptPlaintext))
		)

		suite.NoError(err)
		suite.Equal(o.Len(), n)
	})

	suite.Run("CostTooHigh", func() {
		var (
			o      strings.Builder
			hasher = Bcrypt{Cost: bcrypt.MaxCost + 100}

			_, err = hasher.Hash(&o, []byte(bcryptPlaintext))
		)

		suite.Error(err)
	})
}

func (suite *BcryptTestSuite) TestMatches() {
	suite.Run("Success", func() {
		for _, cost := range []int{0 /* default */, 4, 8} {
			suite.Run(fmt.Sprintf("cost=%d", cost), func() {
				var (
					hashed  = suite.goodHash(cost)
					hasher  = Bcrypt{Cost: cost}
					ok, err = hasher.Matches([]byte(bcryptPlaintext), hashed)
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
					hashed  = suite.goodHash(cost)
					hasher  = Bcrypt{Cost: cost}
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
