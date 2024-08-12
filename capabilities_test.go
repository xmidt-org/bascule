// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type CapabilitiesTestSuite struct {
	suite.Suite
}

func (suite *CapabilitiesTestSuite) TestGetCapabilities() {
	suite.Run("Nil", func() {
		caps, ok := GetCapabilities(nil)
		suite.False(ok)
		suite.Empty(caps)
	})

	suite.Run("NoCapabilities", func() {
		mt := new(mockToken)
		caps, ok := GetCapabilities(mt)
		suite.False(ok)
		suite.Empty(caps)

		mt.AssertExpectations(suite.T())
	})

	suite.Run("EmptyCapabilities", func() {
		mt := new(mockTokenWithCapabilities)
		mt.ExpectCapabilities("one", "two", "three").Once()
		caps, ok := GetCapabilities(mt)
		suite.True(ok)
		suite.Equal([]string{"one", "two", "three"}, caps)

		mt.AssertExpectations(suite.T())
	})

	suite.Run("HasCapabilities", func() {
		mt := new(mockTokenWithCapabilities)
		mt.ExpectCapabilities().Once()
		caps, ok := GetCapabilities(mt)
		suite.True(ok)
		suite.Empty(caps)

		mt.AssertExpectations(suite.T())
	})
}

func TestCapabilities(t *testing.T) {
	suite.Run(t, new(CapabilitiesTestSuite))
}
