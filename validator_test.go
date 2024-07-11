// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ValidatorsTestSuite struct {
	TestSuite
}

func TestValidators(t *testing.T) {
	suite.Run(t, new(ValidatorsTestSuite))
}
