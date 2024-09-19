// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type HasherTestSuite struct {
	TestSuite
}

func (suite *HasherTestSuite) testMatches(cmp Comparer, d Digest) {
	suite.Run("Success", func() {
		suite.NoError(
			Matches(cmp, suite.plaintext, d),
		)
	})

	suite.Run("Fail", func() {
		suite.Error(
			Matches(cmp, suite.plaintext, Digest("this will never match")),
		)
	})
}

func (suite *HasherTestSuite) TestMatches() {
	suite.Run("Default", func() {
		suite.testMatches(nil, suite.goodHash(
			Default().Hash(suite.plaintext)),
		)
	})

	suite.Run("Custom", func() {
		custom := Bcrypt{Cost: 9}
		suite.testMatches(custom,
			suite.goodHash(custom.Hash(suite.plaintext)),
		)
	})
}

func TestHasher(t *testing.T) {
	suite.Run(t, new(HasherTestSuite))
}

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

	hasher   Hasher
	comparer Comparer
}

// SetupSuite initializes a hasher and comparer to use when verifying
// and creating digests.
func (suite *CredentialsTestSuite[C]) SetupSuite() {
	suite.hasher = Bcrypt{Cost: bcrypt.MinCost}
	suite.comparer = Bcrypt{Cost: bcrypt.MinCost}
}

// assertLen asserts that the credentials under test have the given length.
func (suite *CredentialsTestSuite[C]) assertLen(expected int) {
	suite.Equal(expected, suite.credentials.Len())
}

// exists asserts that a given principal exists with the given Digest.
func (suite *CredentialsTestSuite[C]) exists(principal string, expected Digest) {
	d, ok := suite.credentials.Get(principal)
	suite.Require().True(ok)
	suite.Require().Equal(expected, d)
}

// notExists asserts that the given principal did not exist.
func (suite *CredentialsTestSuite[C]) notExists(principal string) {
	d, ok := suite.credentials.Get(principal)
	suite.Require().False(ok)
	suite.Require().Empty(d)
}

// deleteExists deletes the given principal and asserts that the principal
// did exist.
func (suite *CredentialsTestSuite[C]) deleteExists(principal string, expected Digest) {
	original := suite.credentials.Len()
	d, ok := suite.credentials.Delete(principal)
	suite.Require().True(ok)
	suite.Equal(original, suite.credentials.Len()+1)
	suite.Require().Equal(expected, d)
}

// deleteNotExists deletes the given principal, asserting that the deletion did
// not modify the Principals because the principal did not exist.
func (suite *CredentialsTestSuite[C]) deleteNotExists(principal string) {
	original := suite.credentials.Len()
	d, ok := suite.credentials.Delete(principal)
	suite.Require().False(ok)
	suite.Empty(d)
	suite.Equal(original, suite.credentials.Len())
}

// defaultHash creates a distinct hash of the suite plaintext for testing.
func (suite *CredentialsTestSuite[C]) defaultHash() Digest {
	return suite.goodHash(
		suite.hasher.Hash(
			suite.plaintext,
		),
	)
}

// defaultMatch asserts that the given principal matches with the defaults.
func (suite *CredentialsTestSuite[C]) defaultMatch(principal string) {
	suite.NoError(
		suite.credentials.Matches(suite.comparer, principal, suite.plaintext),
	)
}

// defaultNoMatch tests if the principal does not match against the defaults.
// The match error is returned for further asserts.
func (suite *CredentialsTestSuite[C]) defaultNoMatch(principal string) error {
	err := suite.credentials.Matches(suite.comparer, principal, suite.plaintext)
	suite.Require().Error(err)
	return err
}

func (suite *CredentialsTestSuite[C]) TestGetSetDelete() {
	suite.T().Log("empty")
	suite.assertLen(0)
	suite.deleteNotExists("joe")

	suite.T().Log("add")
	joeDigest := suite.defaultHash()
	suite.credentials.Set("joe", joeDigest)
	suite.assertLen(1)
	suite.exists("joe", joeDigest)

	suite.T().Log("add another")
	fredDigest := suite.defaultHash()
	suite.credentials.Set("fred", fredDigest)
	suite.assertLen(2)
	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)

	suite.T().Log("replace")
	newJoeDigest := suite.defaultHash()
	suite.Require().NotEqual(newJoeDigest, joeDigest) // hashes should always generate salt to make them distinct
	suite.credentials.Set("joe", newJoeDigest)
	suite.assertLen(2)
	suite.exists("joe", newJoeDigest)
	suite.exists("fred", fredDigest)

	suite.T().Log("delete a principal")
	suite.deleteExists("fred", fredDigest)
	suite.assertLen(1)
	suite.exists("joe", newJoeDigest)
}

func (suite *CredentialsTestSuite[C]) TestMatches() {
	// initial condition:
	suite.defaultNoMatch("joe")

	suite.credentials.Set("joe", suite.defaultHash())
	suite.defaultMatch("joe")

	suite.credentials.Set("fred", suite.defaultHash())
	suite.defaultMatch("joe")
	suite.defaultMatch("fred")

	suite.credentials.Set("joe", suite.goodHash(Default().Hash([]byte("a different password"))))
	suite.defaultNoMatch("joe")
	suite.defaultMatch("fred")
}

func (suite *CredentialsTestSuite[C]) TestUpdate() {
	suite.credentials.Update(nil)
	suite.assertLen(0)

	joeDigest := suite.defaultHash()
	fredDigest := suite.defaultHash()
	suite.credentials.Update(Principals{
		"joe":  joeDigest,
		"fred": fredDigest,
	})

	suite.assertLen(2)
	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)

	joeDigest = suite.defaultHash()
	moeDigest := suite.defaultHash()
	suite.credentials.Update(Principals{
		"joe": joeDigest,
		"moe": moeDigest,
	})

	suite.assertLen(3)
	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)
	suite.exists("moe", moeDigest)
}

// TestMarshalJSON can happen here since we can marshal things abstractly.
func (suite *CredentialsTestSuite[C]) TestMarshalJSON() {
	var (
		joeDigest  = suite.defaultHash()
		fredDigest = suite.defaultHash()

		expectedJSON = fmt.Sprintf(
			`{
				"joe": "%s",
				"fred": "%s"
			}`,
			joeDigest,
			fredDigest,
		)
	)

	suite.credentials.Set("joe", joeDigest)
	suite.credentials.Set("fred", fredDigest)

	data, err := json.Marshal(suite.credentials)
	suite.Require().NoError(err)
	suite.JSONEq(expectedJSON, string(data))
}
