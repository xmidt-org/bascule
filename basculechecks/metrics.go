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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
)

// Names for our metrics
const (
	AuthCapabilityCheckOutcome = "auth_capability_check"
)

// labels
const (
	OutcomeLabel   = "outcome"
	ReasonLabel    = "reason"
	ClientIDLabel  = "clientid"
	EndpointLabel  = "endpoint"
	MethodLabel    = "method"
	PartnerIDLabel = "partnerid"
	ServerLabel    = "server"
)

// outcomes
const (
	RejectedOutcome = "rejected"
	AcceptedOutcome = "accepted"
	// reasons
	TokenMissing             = "auth_missing"
	UndeterminedPartnerID    = "undetermined_partner_ID"
	UndeterminedCapabilities = "undetermined_capabilities"
	EmptyCapabilitiesList    = "empty_capabilities_list"
	MissingValues            = "auth_is_missing_values"
	NoEndpointChecker        = "no_capability_checker"
	NoCapabilitiesMatch      = "no_capabilities_match"
	EmptyParsedURL           = "empty_parsed_URL"
)

// help messages
const (
	capabilityCheckHelpMsg = "Counter for the capability checker, providing outcome information by client, partner, and endpoint"
)

// ProvideMetrics provides the metrics relevant to this package as uber/fx options.
// This is now deprecated in favor of ProvideMetricsVec.
func ProvideMetrics() fx.Option {
	return fx.Options(
		touchstone.CounterVec(prometheus.CounterOpts{
			Name:        AuthCapabilityCheckOutcome,
			Help:        capabilityCheckHelpMsg,
			ConstLabels: nil,
		}, ServerLabel, OutcomeLabel, ReasonLabel, ClientIDLabel,
			PartnerIDLabel, EndpointLabel, MethodLabel),
	)
}

// AuthCapabilityCheckMeasures describes the defined metrics that will be used by clients
type AuthCapabilityCheckMeasures struct {
	fx.In

	CapabilityCheckOutcome *prometheus.CounterVec `name:"auth_capability_check"`
}
