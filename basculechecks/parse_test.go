/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package basculechecks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeterminePartnerMetric(t *testing.T) {
	tests := []struct {
		description    string
		partnersInput  []string
		expectedResult string
	}{
		{
			description:    "No Partners",
			expectedResult: "none",
		},
		{
			description:    "one wildcard",
			partnersInput:  []string{"*"},
			expectedResult: "wildcard",
		},
		{
			description:    "one partner",
			partnersInput:  []string{"TestPartner"},
			expectedResult: "TestPartner",
		},
		{
			description:    "many partners",
			partnersInput:  []string{"partner1", "partner2", "partner3"},
			expectedResult: "many",
		},
		{
			description:    "many partners with wildcard",
			partnersInput:  []string{"partner1", "partner2", "partner3", "*"},
			expectedResult: "wildcard",
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			partner := DeterminePartnerMetric(tc.partnersInput)
			assert.Equal(tc.expectedResult, partner)
		})
	}
}

func TestDetermineEndpointMetric(t *testing.T) {
}
