// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"

	"golang.org/x/crypto/bcrypt"
)

// CredentialsTestSuite runs a standard battery of tests against
// a Credentials implementation.
//
// Tests of UnmarshalJSON need to be done in tests of concrete types
// due to the way unmarshalling works in golang.
type CredentialsTestSuite[C Credentials] struct {
	TestSuite

	// Implementations should supply SetupTest and SetupSubTest
	// methods that populate this member. Don't forget to call
	// TestSuite.SetupTest and TestSuite.SetupSubTest!
	credentials C

	testCtx context.Context
	hasher  Hasher
}

// SetupSuite initializes a hasher and comparer to use when verifying
// and creating digests.
func (suite *CredentialsTestSuite[C]) SetupSuite() {
	suite.testCtx = context.Background()
	suite.hasher = Bcrypt{Cost: bcrypt.MinCost}
}

// exists asserts that a given principal exists with the given Digest.
func (suite *CredentialsTestSuite[C]) exists(principal string, expected Digest) {
	d, ok := suite.credentials.Get(suite.testCtx, principal)
	suite.Require().True(ok)
	suite.Require().Equal(expected, d)
}

// notExists asserts that the given principal did not exist.
func (suite *CredentialsTestSuite[C]) notExists(principal string) {
	d, ok := suite.credentials.Get(suite.testCtx, principal)
	suite.Require().False(ok)
	suite.Require().Empty(d)
}

// defaultHash creates a distinct hash of the suite plaintext for testing.
func (suite *CredentialsTestSuite[C]) defaultHash() Digest {
	return suite.goodHash(
		suite.hasher.Hash(
			suite.plaintext,
		),
	)
}

func (suite *CredentialsTestSuite[C]) TestGetSetDelete() {
	suite.T().Log("delete from empty")
	suite.credentials.Delete(suite.testCtx, "joe")

	suite.T().Log("add")
	joeDigest := suite.defaultHash()
	suite.credentials.Set(suite.testCtx, "joe", joeDigest)
	suite.exists("joe", joeDigest)

	suite.T().Log("add another")
	fredDigest := suite.defaultHash()
	suite.credentials.Set(suite.testCtx, "fred", fredDigest)
	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)

	suite.T().Log("replace")
	newJoeDigest := suite.defaultHash()
	suite.Require().NotEqual(newJoeDigest, joeDigest) // hashes should always generate salt to make them distinct
	suite.credentials.Set(suite.testCtx, "joe", newJoeDigest)
	suite.exists("joe", newJoeDigest)
	suite.exists("fred", fredDigest)

	suite.T().Log("delete a principal")
	suite.credentials.Delete(suite.testCtx, "fred")
	suite.notExists("fred")
	suite.exists("joe", newJoeDigest)
}

func (suite *CredentialsTestSuite[C]) TestUpdate() {
	suite.credentials.Update(suite.testCtx, nil)

	joeDigest := suite.defaultHash()
	fredDigest := suite.defaultHash()
	suite.credentials.Update(suite.testCtx, Principals{
		"joe":  joeDigest,
		"fred": fredDigest,
	})

	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)

	joeDigest = suite.defaultHash()
	moeDigest := suite.defaultHash()
	suite.credentials.Update(suite.testCtx, Principals{
		"joe": joeDigest,
		"moe": moeDigest,
	})

	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)
	suite.exists("moe", moeDigest)
}
