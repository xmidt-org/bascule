// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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
				server:   defaultServer,
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
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			m, err := NewMetricValidator(tc.checker, tc.measures, tc.options...)
			assert.Equal(tc.expectedValidator, m)
			assert.True(errors.Is(err, tc.expectedErr),
				fmt.Errorf("error [%v] doesn't match expected error [%v]",
					err, tc.expectedErr),
			)
		})
	}
}
