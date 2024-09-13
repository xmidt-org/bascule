// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PrincipalsTestSuite struct {
	TestSuite
}

// exists asserts that a given principal exists, and returns the Digest.
func (suite *PrincipalsTestSuite) exists(p Principals, principal string) Digest {
	d, ok := p.Get(principal)
	suite.Require().True(ok)
	return d
}

// notExists asserts that the given principal did not exist.
func (suite *PrincipalsTestSuite) notExists(p Principals, principal string) {
	d, ok := p.Get(principal)
	suite.Require().False(ok)
	suite.Require().Empty(d)
}

// deleteExists deletes the given principal and asserts that the principal
// did exist.
func (suite *PrincipalsTestSuite) deleteExists(p Principals, principal string) Digest {
	original := p.Len()
	d, ok := p.Delete(principal)
	suite.Require().True(ok)
	suite.Equal(original, p.Len()+1)

	return d
}

// deleteNotExists deletes the given principal, asserting that the deletion did
// not modify the Principals because the principal did not exist.
func (suite *PrincipalsTestSuite) deleteNotExists(p Principals, principal string) {
	original := p.Len()
	d, ok := p.Delete(principal)
	suite.Require().False(ok)
	suite.Empty(d)
	suite.Equal(original, p.Len())
}

func (suite *PrincipalsTestSuite) TestGetSetDelete() {
	suite.T().Log("empty Principals")
	var p Principals
	suite.Zero(p.Len())
	suite.notExists(p, "joe")
	suite.deleteNotExists(p, "joe")

	suite.T().Log("add a principal")
	joeDigest := suite.goodHash(Default().Hash(suite.plaintext))
	p.Set("joe", joeDigest)
	suite.Equal(1, p.Len())
	suite.Equal(joeDigest, suite.exists(p, "joe"))

	suite.T().Log("add another principal")
	fredDigest := suite.goodHash(Default().Hash(suite.plaintext))
	p.Set("fred", fredDigest)
	suite.Equal(2, p.Len())
	suite.Equal(joeDigest, suite.exists(p, "joe"))
	suite.Equal(fredDigest, suite.exists(p, "fred"))

	suite.T().Log("replace a principal")
	newJoeDigest := suite.goodHash(Default().Hash(suite.plaintext))
	suite.Require().NotEqual(newJoeDigest, joeDigest) // hashes should always generate salt to make them distinct
	p.Set("joe", newJoeDigest)
	suite.Equal(2, p.Len())
	suite.Equal(newJoeDigest, suite.exists(p, "joe"))
	suite.Equal(fredDigest, suite.exists(p, "fred"))

	suite.T().Log("delete a principal")
	suite.Equal(fredDigest, suite.deleteExists(p, "fred"))
	suite.Equal(1, p.Len())
	suite.Equal(newJoeDigest, suite.exists(p, "joe"))
}

func (suite *PrincipalsTestSuite) testMatches(cmp Comparer, d Digest) {
	p := Principals{
		"joe": d,
	}

	suite.match(
		p.Matches(cmp, "joe", suite.plaintext),
	)

	suite.noMatch(
		p.Matches(cmp, "joe", []byte("this will never match")),
	)

	suite.noMatch(
		p.Matches(cmp, "doesnotexist", suite.plaintext),
	)
}

func (suite *PrincipalsTestSuite) TestMatches() {
	suite.Run("Default", func() {
		suite.testMatches(nil,
			suite.goodHash(Default().Hash(suite.plaintext)),
		)
	})

	suite.Run("Custom", func() {
		custom := Bcrypt{Cost: 8}
		suite.testMatches(custom,
			suite.goodHash(custom.Hash(suite.plaintext)),
		)
	})
}

func TestPrincipals(t *testing.T) {
	suite.Run(t, new(PrincipalsTestSuite))
}
