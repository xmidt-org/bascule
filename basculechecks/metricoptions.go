// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import "regexp"

const (
	defaultServer = "primary"
)

// MetricOption provides a way to configure a MetricValidator.
type MetricOption func(*MetricValidator)

// MonitorOnly modifies the MetricValidator to never return an error when the
// Check() function is called.
func MonitorOnly() MetricOption {
	return func(m *MetricValidator) {
		m.errorOut = false
	}
}

// WithServer provides the server name to be used in the metric label.
func WithServer(s string) MetricOption {
	return func(m *MetricValidator) {
		if len(s) > 0 {
			m.server = s
		}
	}
}

// WithEndpoints provides the endpoint buckets to use in the endpoint metric
// label.  The endpoint bucket found for a request is also passed to the
// CapabilitiesChecker.
func WithEndpoints(e []*regexp.Regexp) MetricOption {
	return func(m *MetricValidator) {
		if len(e) != 0 {
			m.endpoints = e
		}
	}
}

// NewMetricValidator creates a MetricValidator given a CapabilitiesChecker,
// measures, and options to configure it.  The checker and measures cannot be
// nil.
func NewMetricValidator(checker CapabilitiesChecker, measures *AuthCapabilityCheckMeasures, options ...MetricOption) (*MetricValidator, error) {
	if checker == nil {
		return nil, ErrNilChecker
	}

	if measures == nil {
		return nil, ErrNilMeasures
	}

	m := MetricValidator{
		c:        checker,
		measures: measures,
		errorOut: true,
		server:   defaultServer,
	}

	for _, o := range options {
		if o != nil {
			o(&m)
		}
	}
	return &m, nil
}
