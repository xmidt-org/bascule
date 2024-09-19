// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type StoreTestSuite struct {
	CredentialsTestSuite[*Store]
}

func (suite *StoreTestSuite) SetupSubTest() {
	suite.SetupTest()
}

func (suite *StoreTestSuite) SetupTest() {
	suite.CredentialsTestSuite.SetupTest()
	suite.credentials = new(Store)
}

func (suite *StoreTestSuite) TestMarshalJSON() {
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

	suite.credentials.Set(suite.testCtx, "joe", joeDigest)
	suite.credentials.Set(suite.testCtx, "fred", fredDigest)
	actualJSON, err := json.Marshal(suite.credentials)

	suite.Require().NoError(err)
	suite.JSONEq(expectedJSON, string(actualJSON))
}

func (suite *StoreTestSuite) TestUnmarshalJSON() {
	var (
		joeDigest  = suite.defaultHash()
		fredDigest = suite.defaultHash()

		jsonValue = fmt.Sprintf(
			`{
				"joe": "%s",
				"fred": "%s"
			}`,
			joeDigest,
			fredDigest,
		)
	)

	err := json.Unmarshal([]byte(jsonValue), suite.credentials)
	suite.Require().NoError(err)
	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)
}

func TestStore(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}
