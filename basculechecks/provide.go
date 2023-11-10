// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

// ProvideMetricValidator is an uber fx Provide() function that builds a
// MetricValidator given the dependencies needed.
func ProvideMetricValidator(optional bool) fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name: "bascule_validator_capabilities",
			Target: func(in MetricValidatorIn) (bascule.Validator, error) {
				if optional && in.Checker == nil {
					return nil, nil
				}
				return NewMetricValidator(in.Checker, &in.Measures, in.Options...)
			},
		},
	)
}

// ProvideCapabilitiesMapValidator is an uber fx Provide() function that builds
// a MetricValidator that uses a CapabilitiesMap and ConstChecks, using the
// configuration found at the key provided.
func ProvideCapabilitiesMapValidator() fx.Option {
	return fx.Options(
		fx.Provide(
			NewCapabilitiesMap,
		),
		ProvideMetricValidator(false),
	)
}

// ProvideRegexCapabilitiesValidator is an uber fx Provide() function that
// builds a MetricValidator that uses a CapabilitiesValidator and
// RegexEndpointCheck, using the configuration found at the key provided.
func ProvideRegexCapabilitiesValidator() fx.Option {
	return fx.Options(
		fx.Provide(
			NewCapabilitiesValidator,
		),
		ProvideMetricValidator(true),
	)
}
