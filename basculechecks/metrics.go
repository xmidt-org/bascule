// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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

// label values
const (
	// outcomes
	RejectedOutcome = "rejected"
	AcceptedOutcome = "accepted"
	// reasons
	UnknownReason            = "unknown"
	TokenMissing             = "auth_missing"
	UndeterminedPartnerID    = "undetermined_partner_ID"
	UndeterminedCapabilities = "undetermined_capabilities"
	EmptyCapabilitiesList    = "empty_capabilities_list"
	MissingValues            = "auth_is_missing_values"
	NoEndpointChecker        = "no_capability_checker"
	NoCapabilitiesMatch      = "no_capabilities_match"
	EmptyParsedURL           = "empty_parsed_URL"
	// partners
	NonePartner     = "none"
	WildcardPartner = "wildcard"
	ManyPartner     = "many"
	// endpoints
	NoneEndpoint          = "no_endpoints"
	NotRecognizedEndpoint = "not_recognized"
)

// help messages
const (
	capabilityCheckHelpMsg = "Counter for the capability checker, providing outcome information by client, partner, and endpoint"
)

// ProvideMetrics provides the metrics relevant to this package as uber/fx
// options.
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

// AuthCapabilityCheckMeasures describes the defined metrics that will be used
// by clients.
type AuthCapabilityCheckMeasures struct {
	fx.In

	CapabilityCheckOutcome *prometheus.CounterVec `name:"auth_capability_check"`
}
