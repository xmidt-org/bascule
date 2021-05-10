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
	"fmt"

	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

type MetricValidatorIn struct {
	fx.In
	Checker  CapabilitiesChecker
	Measures AuthCapabilityCheckMeasures
	Options  []MetricOption `group:"bascule_capability_options" optional:"true"`
}

func ProvideMetricValidator(server string) fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name: fmt.Sprintf("%s_bascule_validator_capabilities", server),
			Target: func(in MetricValidatorIn) (bascule.Validator, error) {
				options := append(in.Options, WithServer(server))
				return NewMetricValidator(in.Checker, &in.Measures, options...)
			},
		},
	)
}
