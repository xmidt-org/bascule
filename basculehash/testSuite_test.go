// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"github.com/stretchr/testify/suite"
)

// TestSuite has common infrastructure for hashing test suites.
type TestSuite struct {
	suite.Suite

	plaintext []byte
}

func (suite *TestSuite) SetupSubTest() {
	suite.SetupTest()
}

func (suite *TestSuite) SetupTest() {
	suite.plaintext = []byte("here is some plaintext")
}

// goodHash asserts that a hasher did create a digest successfully,
// and returns that Digest.
func (suite *TestSuite) goodHash(h Hasher, plaintext []byte) Digest {
	d, err := h.Hash(plaintext)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(d)
	return d
}

// badHash asserts that the hash fails.  The digest and error are returned
// for any future asserts.
func (suite *TestSuite) badHash(h Hasher, plaintext []byte) (Digest, error) {
	d, err := h.Hash(plaintext)
	suite.Require().Error(err)
	return d, err // hashers are not required to return empty digests on error
}
