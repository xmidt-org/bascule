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
	ServerLabel  = "server"
)

// help messages
const (
	authValidationOutcomeHelpMsg = "Counter for success and failure reason results through bascule"
	nbfHelpMsg                   = "Difference (in seconds) between time of JWT validation and nbf (including leeway)"
	expHelpMsg                   = "Difference (in seconds) between time of JWT validation and exp (including leeway)"
)

// ProvideMetrics provides the metrics relevant to this package as uber/fx
// options. The provided metrics are prometheus vectors which gives access to
// more advanced operations such as CurryWith(labels).
func ProvideMetrics() fx.Option {
	return fx.Provide(
		touchstone.CounterVec(
			prometheus.CounterOpts{
				Name:        AuthValidationOutcome,
				Help:        authValidationOutcomeHelpMsg,
				ConstLabels: nil,
			}, ServerLabel, OutcomeLabel),
		touchstone.HistogramVec(
			prometheus.HistogramOpts{
				Name:    NBFHistogram,
				Help:    nbfHelpMsg,
				Buckets: []float64{-61, -11, -2, -1, 0, 9, 60}, // defines the upper inclusive (<=) bounds
			}, ServerLabel),
		touchstone.HistogramVec(
			prometheus.HistogramOpts{
				Name:    EXPHistogram,
				Help:    expHelpMsg,
				Buckets: []float64{-61, -11, -2, -1, 0, 9, 60},
			}, ServerLabel),
	)
}

// AuthValidationMeasures describes the defined metrics that will be used by clients
type AuthValidationMeasures struct {
	fx.In

	NBFHistogram      prometheus.ObserverVec `name:"auth_from_nbf_seconds"`
	EXPHistogram      prometheus.ObserverVec `name:"auth_from_exp_seconds"`
	ValidationOutcome *prometheus.CounterVec `name:"auth_validation"`
}
