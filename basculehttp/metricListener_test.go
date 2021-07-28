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

package basculehttp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/touchstone/touchtest"
)

const testServerName = "testserver"

func TestNewMetricListener(t *testing.T) {
	m := &AuthValidationMeasures{}
	tests := []struct {
		description            string
		measures               *AuthValidationMeasures
		options                []Option
		expectedMetricListener *MetricListener
		expectedErr            error
	}{
		{
			description: "Success",
			measures:    m,
			options: []Option{
				WithServer(testServerName),
				WithServer(""),
			},
			expectedMetricListener: &MetricListener{
				server:   testServerName,
				measures: m,
			},
		},
		{
			description: "Success with defaults",
			measures:    m,
			expectedMetricListener: &MetricListener{
				server:   defaultServer,
				measures: m,
			},
		},
		{
			description: "Nil measures error",
			expectedErr: ErrNilMeasures,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			ml, err := NewMetricListener(tc.measures, tc.options...)
			assert.Equal(tc.expectedMetricListener, ml)
			if tc.expectedErr == nil {
				assert.NoError(err)
				return
			}
			assert.True(errors.Is(err, tc.expectedErr),
				fmt.Errorf("error [%v] doesn't contain error [%v] in its err chain",
					err, tc.expectedErr),
			)
		})
	}
}

func TestOnAuthenticated(t *testing.T) {
	tests := []struct {
		description     string
		token           bascule.Token
		expectedOutcome string
	}{
		{
			description:     "Success",
			token:           bascule.NewToken("test", "princ", nil),
			expectedOutcome: AcceptedOutcome,
		},
		{
			description:     "Success with empty token",
			expectedOutcome: EmptyOutcome,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			testAssert := touchtest.New(t)

			// set up metric stuff.
			expectedRegistry := prometheus.NewPedanticRegistry()
			expectedCounter := prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: "testCounter",
					Help: "testCounter",
				},
				[]string{ServerLabel, OutcomeLabel},
			)
			expectedRegistry.Register(expectedCounter)
			expectedCounter.With(prometheus.Labels{
				ServerLabel:  testServerName,
				OutcomeLabel: tc.expectedOutcome,
			}).Inc()
			actualRegistry := prometheus.NewPedanticRegistry()
			mockMeasures := AuthValidationMeasures{
				ValidationOutcome: prometheus.NewCounterVec(
					prometheus.CounterOpts{
						Name: "testCounter",
						Help: "testCounter",
					},
					[]string{ServerLabel, OutcomeLabel},
				),
			}
			actualRegistry.MustRegister(mockMeasures.ValidationOutcome)

			m := &MetricListener{
				server:   testServerName,
				measures: &mockMeasures,
			}
			m.OnAuthenticated(bascule.Authentication{Token: tc.token})
			testAssert.Expect(expectedRegistry)
			assert.True(testAssert.GatherAndCompare(actualRegistry))
		})
	}
}
func TestOnErrorResponse(t *testing.T) {
	tests := []struct {
		description string
		reason      ErrorResponseReason
	}{
		{
			description: "Checks failed",
			reason:      ChecksFailed,
		},
		{
			description: "Get URL failed",
			reason:      GetURLFailed,
		},
		{
			description: "Key not supported",
			reason:      KeyNotSupported,
		},
		{
			description: "Negative unknown reason",
			reason:      -1,
		},
		{
			description: "Big number unknown reason",
			reason:      10000000,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			testAssert := touchtest.New(t)

			// set up metric stuff.
			expectedRegistry := prometheus.NewPedanticRegistry()
			expectedCounter := prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: "testCounter",
					Help: "testCounter",
				},
				[]string{ServerLabel, OutcomeLabel},
			)
			expectedRegistry.Register(expectedCounter)
			expectedCounter.With(prometheus.Labels{
				ServerLabel:  testServerName,
				OutcomeLabel: tc.reason.String(),
			}).Inc()
			actualRegistry := prometheus.NewPedanticRegistry()
			mockMeasures := AuthValidationMeasures{
				ValidationOutcome: prometheus.NewCounterVec(
					prometheus.CounterOpts{
						Name: "testCounter",
						Help: "testCounter",
					},
					[]string{ServerLabel, OutcomeLabel},
				),
			}
			actualRegistry.MustRegister(mockMeasures.ValidationOutcome)

			m := &MetricListener{
				server:   testServerName,
				measures: &mockMeasures,
			}
			m.OnErrorResponse(tc.reason, errors.New("testing error"))
			testAssert.Expect(expectedRegistry)
			assert.True(testAssert.GatherAndCompare(actualRegistry))
		})
	}
}
