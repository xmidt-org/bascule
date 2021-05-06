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
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMetricValidator(t *testing.T) {
	c := &CapabilitiesValidator{}
	m := &AuthCapabilityCheckMeasures{}
	e := []*regexp.Regexp{regexp.MustCompile(".*")}
	s := "testserverrr"
	tests := []struct {
		description       string
		checker           CapabilitiesChecker
		measures          *AuthCapabilityCheckMeasures
		options           []MetricOption
		expectedValidator *MetricValidator
		expectedErr       error
	}{
		{
			description: "Success",
			checker:     c,
			measures:    m,
			options: []MetricOption{
				MonitorOnly(),
				WithServer(s),
				WithServer(""),
				WithEndpoints(e),
				WithEndpoints(nil),
			},
			expectedValidator: &MetricValidator{
				c:         c,
				measures:  m,
				server:    s,
				endpoints: e,
				errorOut:  false,
			},
		},
		{
			description: "Success with defaults",
			checker:     c,
			measures:    m,
			expectedValidator: &MetricValidator{
				c:        c,
				measures: m,
				errorOut: true,
			},
		},
		{
			description: "Nil Checker Error",
			measures:    m,
			expectedErr: ErrNilChecker,
		},
		{
			description: "Nil Measures Error",
			checker:     c,
			expectedErr: ErrNilMeasures,
		},
	}
	for _, tc := range tests {
		assert := assert.New(t)
		m, err := NewMetricValidator(tc.checker, tc.measures, tc.options...)
		assert.Equal(tc.expectedValidator, m)
		assert.True(errors.Is(err, tc.expectedErr),
			fmt.Errorf("error [%v] doesn't match expected error [%v]",
				err, tc.expectedErr),
		)
	}
}
