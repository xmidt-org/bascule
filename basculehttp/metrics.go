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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
)

// Names for our metrics
const (
	AuthValidationOutcome = "auth_validation"
	NBFHistogram          = "auth_from_nbf_seconds"
	EXPHistogram          = "auth_from_exp_seconds"
)

// labels
const (
	OutcomeLabel = "outcome"
)

// AuthValidationMeasures describes the defined metrics that will be used by clients
type AuthValidationMeasures struct {
	fx.In

	NBFHistogram      prometheus.Observer    `name:"auth_from_nbf_seconds"`
	EXPHistogram      prometheus.Observer    `name:"auth_from_exp_seconds"`
	ValidationOutcome *prometheus.CounterVec `name:"auth_validation"`
}

// NewAuthValidationMeasures realizes desired metrics
func NewAuthValidationMeasures(f *touchstone.Factory) (*AuthValidationMeasures, error) {
	var (
		m   AuthValidationMeasures
		err error
	)
	m.NBFHistogram, err = f.NewHistogram(prometheus.HistogramOpts{
		Name:    NBFHistogram,
		Help:    "Difference (in seconds) between time of JWT validation and nbf (including leeway)",
		Buckets: []float64{-61, -11, -2, -1, 0, 9, 60}, // defines the upper inclusive (<=) bounds
	})
	if err != nil {
		return nil, err
	}

	m.EXPHistogram, err = f.NewHistogram(prometheus.HistogramOpts{
		Name:    EXPHistogram,
		Help:    "Difference (in seconds) between time of JWT validation and exp (including leeway)",
		Buckets: []float64{-61, -11, -2, -1, 0, 9, 60},
	})
	if err != nil {
		return nil, err
	}

	m.ValidationOutcome, err = f.NewCounterVec(prometheus.CounterOpts{
		Name: AuthValidationOutcome,
		Help: "Counter for the capability checker, providing outcome information by client, partner, and endpoint",
	}, OutcomeLabel)
	if err != nil {
		return nil, err
	}

	return &m, nil
}
