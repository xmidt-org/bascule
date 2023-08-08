// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"regexp"
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
			expectedResult: NonePartner,
		},
		{
			description:    "one wildcard",
			partnersInput:  []string{Wildcard},
			expectedResult: WildcardPartner,
		},
		{
			description:    "one partner",
			partnersInput:  []string{"TestPartner"},
			expectedResult: "TestPartner",
		},
		{
			description:    "many partners",
			partnersInput:  []string{"partner1", "partner2", "partner3"},
			expectedResult: ManyPartner,
		},
		{
			description:    "many partners with wildcard",
			partnersInput:  []string{"partner1", "partner2", "partner3", Wildcard},
			expectedResult: WildcardPartner,
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
	var (
		goodURL          = "/asnkfn/aefkijeoij/aiogj"
		matchingURL      = "/fnvvds jkfji/mac:12345544322345334/geigosj"
		matchingEndpoint = `/fnvvds jkfji/.*/geigosj\b`
		matchingRegex    = regexp.MustCompile(matchingEndpoint)
		matchingParsed   = `/fnvvds_jkfji/.*/geigosj\b`
		unusedEndpoint   = `/a/b\b`
		unusedRegex      = regexp.MustCompile(unusedEndpoint)
	)

	tests := []struct {
		description      string
		endpoints        []*regexp.Regexp
		u                string
		expectedEndpoint string
	}{
		{
			description:      "No Endpoints",
			u:                goodURL,
			expectedEndpoint: NoneEndpoint,
		},
		{
			description:      "Endpoint Not Recognized",
			endpoints:        []*regexp.Regexp{unusedRegex, matchingRegex},
			u:                goodURL,
			expectedEndpoint: NotRecognizedEndpoint,
		},
		{
			description:      "Endpoint Matched",
			endpoints:        []*regexp.Regexp{unusedRegex, matchingRegex},
			u:                matchingURL,
			expectedEndpoint: matchingParsed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			endpoint := determineEndpointMetric(tc.endpoints, tc.u)
			assert.Equal(tc.expectedEndpoint, endpoint)
		})
	}
}
