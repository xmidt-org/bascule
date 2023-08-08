// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculechecks"
	"go.uber.org/fx"
)

// BearerValidatorsIn is a struct used for uber fx wiring, providing an easy way
// to combine validators meant to be used on bearer tokens.
type BearerValidatorsIn struct {
	fx.In
	Vs           []bascule.Validator `group:"bascule_bearer_validators"`
	Capabilities bascule.Validator   `name:"bascule_validator_capabilities" optional:"true"`
}

// ProvideBasicAuth uses the key given to provide a constructor option to create
// basic tokens and an enforcer option to allow all basic tokens.  For basic
// tokens, the token factory's validation checks are usually all that is needed.
func ProvideBasicAuth(key string) fx.Option {
	return fx.Options(
		ProvideBasicTokenFactory(key),
		fx.Provide(
			fx.Annotated{
				Group: "bascule_enforcer_options",
				Target: func() EOption {
					return WithRules(BasicAuthorization, basculechecks.AllowAll())
				},
			},
		),
	)
}

// ProvideBearerValidator builds some basic validators for bearer tokens and
// then bundles them and any other injected bearer validators to be used against
// bearer tokens.  A enforcer option is provided to configure this in the
// enforcer.
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
				if len(rules) == 0 {
					return nil
				}
				if in.Capabilities != nil {
					rules = append(rules, in.Capabilities)
				}
				return WithRules(BearerAuthorization, bascule.Validators(rules))
			},
		},
	)
}
