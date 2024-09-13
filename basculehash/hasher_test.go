// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type HasherTestSuite struct {
	TestSuite
}

func (suite *HasherTestSuite) testMatches(cmp Comparer, d Digest) {
	suite.Run("Success", func() {
		matched, err := Matches(cmp, suite.plaintext, d)
		suite.True(matched)
		suite.NoError(err)
	})

	suite.Run("Fail", func() {
		matched, err := Matches(cmp, suite.plaintext, Digest("this will never match"))
		suite.False(matched)
		suite.Error(err)
	})
}

func (suite *HasherTestSuite) TestMatches() {
	suite.Run("Default", func() {
		suite.testMatches(nil, suite.goodHash(Default(), suite.plaintext))
	})

	suite.Run("Custom", func() {
		custom := Bcrypt{Cost: 9}
		suite.testMatches(custom, suite.goodHash(custom, suite.plaintext))
	})
}

func TestHasher(t *testing.T) {
	suite.Run(t, new(HasherTestSuite))
}
