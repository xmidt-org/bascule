// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"
)

type SalterTestSuite struct {
	suite.Suite
}

func (suite *SalterTestSuite) testSaltWrite() {
	suite.Run("TooLarge", func() {
		var (
			b bytes.Buffer
			s = make(Salt, MaxSaltLength+1)

			n, err = s.Write(&b)
		)

		suite.ErrorIs(err, ErrMaxSaltLengthExceeded)
		suite.Zero(n)
		suite.Zero(b.Len())
	})

	suite.Run("Success", func() {
		var (
			b bytes.Buffer
			s = Salt{10, 20, 30}

			n, err = s.Write(&b)
		)

		suite.NoError(err)
		suite.Equal(4, n)
		suite.Equal(4, b.Len())
		suite.Equal([]byte{3, 10, 20, 30}, b.Bytes())
	})
}

func (suite *SalterTestSuite) TestSalt() {
	suite.Run("Write", suite.testSaltWrite)
}

func (suite *SalterTestSuite) defaultSalter() Salter {
	salter := DefaultSalter()
	suite.Require().NotNil(salter)
	return salter
}

func (suite *SalterTestSuite) testDefaultSalterGenerate() {
	suite.Run("Zero", func() {
		salter := suite.defaultSalter()

		salt, err := salter.Generate(0)
		suite.Empty(salt)
		suite.NoError(err)
	})

	suite.Run("Negative", func() {
		salter := suite.defaultSalter()

		salt, err := salter.Generate(-1)
		suite.Empty(salt)
		suite.NoError(err)
	})

	suite.Run("TooLarge", func() {
		salter := suite.defaultSalter()

		salt, err := salter.Generate(MaxSaltLength + 1)
		suite.Empty(salt)
		suite.ErrorIs(err, ErrMaxSaltLengthExceeded)
	})

	suite.Run("Success", func() {
		salter := suite.defaultSalter()

		salt, err := salter.Generate(5)
		suite.NoError(err)
		suite.Len(salt, 5)
	})
}

func (suite *SalterTestSuite) TestDefaultSalter() {
	suite.Run("Generate", suite.testDefaultSalterGenerate)
}

func TestSalter(t *testing.T) {
	suite.Run(t, new(SalterTestSuite))
}
