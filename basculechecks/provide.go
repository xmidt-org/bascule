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
	"github.com/xmidt-org/arrange"
	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

type MetricValidatorIn struct {
	fx.In
	Checker  CapabilitiesChecker
	Measures AuthCapabilityCheckMeasures
	Options  []MetricOption `group:"bascule_capability_options"`
}

func ProvideMetricValidator() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name: "bascule_validator_capabilities",
			Target: func(in MetricValidatorIn) (bascule.Validator, error) {
				return NewMetricValidator(in.Checker, &in.Measures, in.Options...)
			},
		},
	)
}

func ProvideCapabilitiesMapValidator(key string) fx.Option {
	return fx.Options(
		fx.Provide(
			arrange.UnmarshalKey(key, CapabilitiesMapConfig{}),
			NewCapabilitiesMap,
		),
		ProvideMetricValidator(),
	)
}

func ProvideRegexCapabilitiesValidator(key string) fx.Option {
	return fx.Options(
		fx.Provide(
			arrange.UnmarshalKey(key, CapabilitiesValidatorConfig{}),
			NewCapabilitiesValidator,
		),
		ProvideMetricValidator(),
	)
}
