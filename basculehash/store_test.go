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
	suite.Equal(2, suite.credentials.Len())
	suite.exists("joe", joeDigest)
	suite.exists("fred", fredDigest)
}

func TestStore(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}
