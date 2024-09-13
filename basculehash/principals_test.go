// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PrincipalsTestSuite struct {
	TestSuite

	hasher Hasher
}

func TestPrincipals(t *testing.T) {
	suite.Run(t, new(PrincipalsTestSuite))
}
