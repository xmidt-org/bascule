// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"
)

type DigestTestSuite struct {
	TestSuite

	digest Digest
}

func (suite *DigestTestSuite) SetupTest() {
	suite.TestSuite.SetupTest()
	suite.digest = suite.goodHash(Default(), suite.plaintext)
}

func (suite *DigestTestSuite) TestCopy() {
	clone := suite.digest.Copy()
	suite.Equal(suite.digest, clone)
	suite.NotSame(suite.digest, clone)
}

func (suite *DigestTestSuite) TestString() {
	suite.Equal(
		suite.digest,
		Digest(suite.digest.String()),
	)
}

func (suite *DigestTestSuite) TestMarshalText() {
	text, err := suite.digest.MarshalText()
	suite.Require().NoError(err)

	var clone Digest
	err = clone.UnmarshalText(text)
	suite.Require().NoError(err)
	suite.Equal(suite.digest, clone)
}

func (suite *DigestTestSuite) TestWriteTo() {
	var o bytes.Buffer
	n, err := suite.digest.WriteTo(&o)
	suite.Equal(int64(len(suite.digest)), n)
	suite.Require().NoError(err)

	suite.Equal(
		suite.digest,
		Digest(o.Bytes()),
	)
}

func TestDigest(t *testing.T) {
	suite.Run(t, new(DigestTestSuite))
}
