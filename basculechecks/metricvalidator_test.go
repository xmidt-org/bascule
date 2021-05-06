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
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/touchstone/touchtest"
)

func TestMetricValidatorCheck(t *testing.T) {
	goodURL, err := url.Parse("/test")
	require.Nil(t, err)
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}
	goodAttributes := bascule.NewAttributes(map[string]interface{}{
		CapabilityKey: capabilities,
		"allowedResources": map[string]interface{}{
			"allowedPartners": []string{"meh"},
		},
	})
	cErr := errWithReason{
		err:    errors.New("check test error"),
		reason: NoCapabilitiesMatch,
	}

	tests := []struct {
		description       string
		includeAuth       bool
		attributes        bascule.Attributes
		checkCallExpected bool
		checkErr          error
		errorOut          bool
		errExpected       bool
		expectedLabels    prometheus.Labels
	}{
		{
			description:       "Success",
			includeAuth:       true,
			attributes:        goodAttributes,
			checkCallExpected: true,
			errorOut:          true,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				PartnerIDLabel: "meh",
				OutcomeLabel:   AcceptedOutcome,
				ReasonLabel:    "",
			},
		},
		{
			description: "Include Auth Error",
			errorOut:    true,
			errExpected: true,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				OutcomeLabel:   RejectedOutcome,
				ReasonLabel:    TokenMissing,
				ClientIDLabel:  "",
				PartnerIDLabel: "",
				EndpointLabel:  "",
				MethodLabel:    "",
			},
		},
		{
			description: "Include Auth Suppressed Error",
			errorOut:    false,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				OutcomeLabel:   AcceptedOutcome,
				ReasonLabel:    TokenMissing,
				ClientIDLabel:  "",
				PartnerIDLabel: "",
				EndpointLabel:  "",
				MethodLabel:    "",
			},
		},
		{
			description: "Prep Metrics Error",
			includeAuth: true,
			attributes:  nil,
			errorOut:    true,
			errExpected: true,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				OutcomeLabel:   RejectedOutcome,
				ReasonLabel:    MissingValues,
				ClientIDLabel:  "princ",
				PartnerIDLabel: "",
				EndpointLabel:  "",
				MethodLabel:    "GET",
			},
		},
		{
			description: "Prep Metrics Suppressed Error",
			includeAuth: true,
			attributes:  nil,
			errorOut:    false,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				OutcomeLabel:   AcceptedOutcome,
				ReasonLabel:    MissingValues,
				ClientIDLabel:  "princ",
				PartnerIDLabel: "",
				EndpointLabel:  "",
				MethodLabel:    "GET",
			},
		},
		{
			description:       "Check Error",
			includeAuth:       true,
			attributes:        goodAttributes,
			checkCallExpected: true,
			checkErr:          cErr,
			errorOut:          true,
			errExpected:       true,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				OutcomeLabel:   RejectedOutcome,
				ReasonLabel:    NoCapabilitiesMatch,
				PartnerIDLabel: "meh",
			},
		},
		{
			description:       "Check Suppressed Error",
			includeAuth:       true,
			attributes:        goodAttributes,
			checkCallExpected: true,
			checkErr:          cErr,
			errorOut:          false,
			expectedLabels: prometheus.Labels{
				ServerLabel:    "testserver",
				OutcomeLabel:   AcceptedOutcome,
				ReasonLabel:    NoCapabilitiesMatch,
				PartnerIDLabel: "meh",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			testAssert := touchtest.New(t)
			expectedRegistry := prometheus.NewPedanticRegistry()
			expectedCounter := prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: "testCounter",
					Help: "testCounter",
				},
				[]string{ServerLabel, OutcomeLabel, ReasonLabel, ClientIDLabel,
					PartnerIDLabel, EndpointLabel, MethodLabel},
			)
			expectedRegistry.Register(expectedCounter)
			actualRegistry := prometheus.NewPedanticRegistry()

			ctx := context.Background()
			auth := bascule.Authentication{
				Token: bascule.NewToken("test", "princ", tc.attributes),
				Request: bascule.Request{
					URL:    goodURL,
					Method: "GET",
				},
			}
			if tc.includeAuth {
				ctx = bascule.WithAuthentication(ctx, auth)
			}
			mockCapabilitiesChecker := new(mockCapabilitiesChecker)
			if tc.checkCallExpected {
				tc.expectedLabels[EndpointLabel] = NoneEndpoint
				tc.expectedLabels[MethodLabel] = auth.Request.Method
				tc.expectedLabels[ClientIDLabel] = auth.Token.Principal()
				mockCapabilitiesChecker.On("CheckAuthentication", mock.Anything, mock.Anything).
					Return(tc.checkErr).Once()
			}

			mockMeasures := AuthCapabilityCheckMeasures{
				CapabilityCheckOutcome: prometheus.NewCounterVec(
					prometheus.CounterOpts{
						Name: "testCounter",
						Help: "testCounter",
					},
					[]string{ServerLabel, OutcomeLabel, ReasonLabel, ClientIDLabel,
						PartnerIDLabel, EndpointLabel, MethodLabel},
				),
			}
			actualRegistry.MustRegister(mockMeasures.CapabilityCheckOutcome)
			expectedCounter.With(tc.expectedLabels).Inc()

			m := MetricValidator{
				c:        mockCapabilitiesChecker,
				measures: &mockMeasures,
				errorOut: tc.errorOut,
				server:   "testserver",
			}
			err := m.Check(ctx, nil)
			mockCapabilitiesChecker.AssertExpectations(t)
			if tc.errExpected {
				assert.NotNil(err)
				return
			}
			assert.Nil(err)
			testAssert.Expect(expectedRegistry)
			assert.True(testAssert.GatherAndCompare(actualRegistry))
		})
	}
}

func TestPrepMetrics(t *testing.T) {
	var (
		goodURL        = "/asnkfn/aefkijeoij/aiogj"
		matchingURL    = "/fnvvdsjkfji/mac:12345544322345334/geigosj"
		client         = "special"
		goodEndpoint   = `/fnvvdsjkfji/.*/geigosj\b`
		goodRegex      = regexp.MustCompile(goodEndpoint)
		unusedEndpoint = `/a/b\b`
		unusedRegex    = regexp.MustCompile(unusedEndpoint)
	)

	tests := []struct {
		description          string
		noPartnerID          bool
		partnerIDs           interface{}
		url                  string
		includeToken         bool
		includeMethod        bool
		includeAttributes    bool
		includeURL           bool
		expectedMetricValues metricValues
		expectedErr          error
	}{
		{
			description:       "Success",
			partnerIDs:        []string{"partner"},
			url:               goodURL,
			includeToken:      true,
			includeMethod:     true,
			includeAttributes: true,
			includeURL:        true,
			expectedMetricValues: metricValues{
				method:    "get",
				endpoint:  NotRecognizedEndpoint,
				partnerID: "partner",
				client:    client,
			},
			expectedErr: nil,
		},
		{
			description:       "Success Abridged URL",
			partnerIDs:        []string{"partner"},
			url:               matchingURL,
			includeToken:      true,
			includeMethod:     true,
			includeAttributes: true,
			includeURL:        true,
			expectedMetricValues: metricValues{
				method:    "get",
				endpoint:  goodEndpoint,
				partnerID: "partner",
				client:    client,
			},
			expectedErr: nil,
		},
		{
			description: "Nil Token Error",
			expectedErr: ErrNoToken,
		},
		{
			description:  "No Method Error",
			includeToken: true,
			expectedMetricValues: metricValues{
				client: client,
			},
			expectedErr: ErrNoMethod,
		},
		{
			description:   "Nil Token Attributes Error",
			url:           goodURL,
			includeToken:  true,
			includeMethod: true,
			expectedMetricValues: metricValues{
				method: "get",
				client: client,
			},
			expectedErr: ErrNilAttributes,
		},
		{
			description:       "No Partner ID Error",
			noPartnerID:       true,
			url:               goodURL,
			includeToken:      true,
			includeMethod:     true,
			includeAttributes: true,
			expectedMetricValues: metricValues{
				method: "get",
				client: client,
			},
			expectedErr: ErrGettingPartnerIDs,
		},
		{
			description:       "Non String Slice Partner ID Error",
			partnerIDs:        []int{0, 1, 2},
			url:               goodURL,
			includeToken:      true,
			includeMethod:     true,
			includeAttributes: true,
			expectedMetricValues: metricValues{
				method: "get",
				client: client,
			},
			expectedErr: ErrPartnerIDsNotStringSlice,
		},
		{
			description:       "Non Slice Partner ID Error",
			partnerIDs:        struct{ string }{},
			url:               goodURL,
			includeToken:      true,
			includeMethod:     true,
			includeAttributes: true,
			expectedMetricValues: metricValues{
				method: "get",
				client: client,
			},
			expectedErr: ErrPartnerIDsNotStringSlice,
		},
		{
			description:       "Nil URL Error",
			partnerIDs:        []string{"partner"},
			url:               goodURL,
			includeToken:      true,
			includeMethod:     true,
			includeAttributes: true,
			expectedMetricValues: metricValues{
				method:    "get",
				partnerID: "partner",
				client:    client,
			},
			expectedErr: ErrNoURL,
		},
	}

	m := MetricValidator{
		endpoints: []*regexp.Regexp{unusedRegex, goodRegex},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			// setup auth
			token := bascule.NewToken("mehType", client, nil)
			if tc.includeAttributes {
				a := map[string]interface{}{
					"allowedResources": map[string]interface{}{
						"allowedPartners": tc.partnerIDs,
					},
				}

				if tc.noPartnerID {
					a["allowedResources"] = 5
				}
				attributes := bascule.NewAttributes(a)
				token = bascule.NewToken("mehType", client, attributes)
			}
			auth := bascule.Authentication{
				Authorization: "testAuth",
				Request:       bascule.Request{},
			}
			if tc.includeToken {
				auth.Token = token
			}
			if tc.includeURL {
				u, err := url.ParseRequestURI(tc.url)
				require.Nil(err)
				auth.Request.URL = u
			}
			if tc.includeMethod {
				auth.Request.Method = "get"
			}

			v, err := m.prepMetrics(auth)
			assert.Equal(tc.expectedMetricValues, v)
			if tc.expectedErr == nil {
				assert.NoError(err)
				return
			}
			assert.True(errors.Is(err, tc.expectedErr),
				fmt.Errorf("error [%v] doesn't contain error [%v] in its err chain",
					err, tc.expectedErr),
			)
			// every error should be a reasoner.
			var r Reasoner
			assert.True(errors.As(err, &r), "expected error to be a Reasoner")
		})
	}
}
