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
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculechecks"
	"go.uber.org/fx"
)

type BearerValidatorsIn struct {
	fx.In
	Vs           []bascule.Validator `group:"bascule_bearer_validators"`
	Capabilities bascule.Validator   `name:"bascule_validator_capabilities" optional:"true"`
}

func ProvideBasicAuth(key string) fx.Option {
	return fx.Options(
		ProvideBasicTokenFactory(key),
		fx.Provide(
			fx.Annotated{
				Group: "primary_bascule_enforcer_options",
				Target: func() EOption {
					return WithRules("Basic", basculechecks.AllowAll())
				},
			},
		),
	)
}

func ProvideBearerValidator() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Group: "bascule_bearer_validators",
			Target: func() bascule.Validator {
				return basculechecks.NonEmptyPrincipal()
			},
		},
		fx.Annotated{
			Group: "bascule_bearer_validators",
			Target: func() bascule.Validator {
				return basculechecks.ValidType([]string{"jwt"})
			},
		},
		fx.Annotated{
			Group: "bascule_enforcer_options",
			Target: func(in BearerValidatorsIn) EOption {
				if len(in.Vs) == 0 {
					return nil
				}
				// don't add any nil validators.
				rules := []bascule.Validator{}
				for _, v := range in.Vs {
					if v != nil {
						rules = append(rules, v)
					}
				}
				if in.Capabilities != nil {
					rules = append(rules, in.Capabilities)
				}
				return WithRules("Bearer", bascule.Validators(rules))
			},
		},
	)
}
