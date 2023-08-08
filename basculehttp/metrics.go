// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
)

// Names for our metrics
const (
	AuthValidationOutcome = "auth_validation"
)

// labels
const (
	OutcomeLabel = "outcome"
	ServerLabel  = "server"
)

// outcome values other than error response reasons
const (
	AcceptedOutcome = "accepted"
	EmptyOutcome    = "accepted_but_empty"
)

// help messages
const (
	authValidationOutcomeHelpMsg = "Counter for success and failure reason results through bascule"
)

// ProvideMetrics provides the metrics relevant to this package as uber/fx
// options. The provided metrics are prometheus vectors which gives access to
// more advanced operations such as CurryWith(labels).
func ProvideMetrics() fx.Option {
	return fx.Options(
		touchstone.CounterVec(
			prometheus.CounterOpts{
				Name:        AuthValidationOutcome,
				Help:        authValidationOutcomeHelpMsg,
				ConstLabels: nil,
			}, ServerLabel, OutcomeLabel),
	)
}

// AuthValidationMeasures describes the defined metrics that will be used by clients
type AuthValidationMeasures struct {
	fx.In

	ValidationOutcome *prometheus.CounterVec `name:"auth_validation"`
}
