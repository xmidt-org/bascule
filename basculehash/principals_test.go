// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PrincipalsTestSuite struct {
	CredentialsTestSuite[Principals]
}

func (suite *PrincipalsTestSuite) SetupSubTest() {
	suite.SetupTest()
}

func (suite *PrincipalsTestSuite) SetupTest() {
	suite.CredentialsTestSuite.SetupTest()
	suite.credentials = Principals{}
}

func TestPrincipals(t *testing.T) {
	suite.Run(t, new(PrincipalsTestSuite))
}
