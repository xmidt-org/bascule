// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

type SchemeTestSuite struct {
	suite.Suite
}

func (suite *SchemeTestSuite) TestUnsupportedSchemeError() {
	use := &UnsupportedSchemeError{
		Scheme: Scheme("Unsupported"),
	}

	suite.Equal(http.StatusUnauthorized, use.StatusCode())
	suite.Contains(use.Error(), "Unsupported")
}

func TestScheme(t *testing.T) {
	suite.Run(t, new(SchemeTestSuite))
}
