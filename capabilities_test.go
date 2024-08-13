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

func (suite *CapabilitiesTestSuite) testGetCapabilitiesNil() {
	caps, ok := GetCapabilities(nil)
	suite.False(ok)
	suite.Empty(caps)
}

func (suite *CapabilitiesTestSuite) testGetCapabilitiesAccessor() {
	suite.Run("NoCapabilities", func() {
		mt := new(mockToken)
		caps, ok := GetCapabilities(mt)
		suite.False(ok)
		suite.Empty(caps)

		mt.AssertExpectations(suite.T())
	})

	suite.Run("EmptyCapabilities", func() {
		mt := new(mockTokenWithCapabilities)
		mt.ExpectCapabilities().Once()
		caps, ok := GetCapabilities(mt)
		suite.True(ok)
		suite.Empty(caps)

		mt.AssertExpectations(suite.T())
	})

	suite.Run("HasCapabilities", func() {
		mt := new(mockTokenWithCapabilities)
		mt.ExpectCapabilities("one", "two", "three").Once()
		caps, ok := GetCapabilities(mt)
		suite.True(ok)
		suite.Equal([]string{"one", "two", "three"}, caps)

		mt.AssertExpectations(suite.T())
	})
}

func (suite *CapabilitiesTestSuite) testGetCapabilitiesStringSlice() {
	suite.Run("Empty", func() {
		caps, ok := GetCapabilities([]string{})
		suite.True(ok)
		suite.Empty(caps)
	})

	suite.Run("NonEmpty", func() {
		caps, ok := GetCapabilities([]string{"one", "two", "three"})
		suite.True(ok)
		suite.Equal([]string{"one", "two", "three"}, caps)
	})
}

func (suite *CapabilitiesTestSuite) testGetCapabilitiesString() {
	caps, ok := GetCapabilities("single")
	suite.True(ok)
	suite.Equal([]string{"single"}, caps)
}

func (suite *CapabilitiesTestSuite) testGetCapabilitiesAnySlice() {
	suite.Run("AllStrings", func() {
		caps, ok := GetCapabilities([]any{"one", "two", "three"})
		suite.True(ok)
		suite.Equal([]string{"one", "two", "three"}, caps)
	})

	suite.Run("NonStrings", func() {
		caps, ok := GetCapabilities([]any{"one", 2.0, 3})
		suite.False(ok)
		suite.Empty(caps)
	})
}

func (suite *CapabilitiesTestSuite) TestGetCapabilities() {
	suite.Run("Nil", suite.testGetCapabilitiesNil)
	suite.Run("Accessor", suite.testGetCapabilitiesAccessor)
	suite.Run("StringSlice", suite.testGetCapabilitiesStringSlice)
	suite.Run("String", suite.testGetCapabilitiesString)
	suite.Run("AnySlice", suite.testGetCapabilitiesAnySlice)
}

func TestCapabilities(t *testing.T) {
	suite.Run(t, new(CapabilitiesTestSuite))
}
