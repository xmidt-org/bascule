// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule/basculechecks"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap/zaptest"
)

func TestProvideBearerMiddleware(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	type In struct {
		fx.In
		AuthChain alice.Chain `name:"auth_chain"`
	}
	result := In{}
	app := fxtest.New(
		t,

		// supplying dependencies
		fx.Supply(zaptest.NewLogger(t)),
		fx.Supply(basculechecks.CapabilitiesMapConfig{
			Endpoints: map[string]string{
				".*/a/.*": "whatsup",
				".*/b/.*": "nm",
			},
			Default: "eh",
		}),
		touchstone.Provide(),
		fx.Provide(
			fx.Annotated{
				Name: "default_key_id",
				Target: func() string {
					return "current"
				},
			},
		),

		// the parts we care about
		ProvideMetrics(),
		ProvideBearerTokenFactory(false),
		basculechecks.ProvideMetrics(),
		basculechecks.ProvideCapabilitiesMapValidator(),
		ProvideBearerValidator(),
		ProvideServerChain(),

		fx.Invoke(
			func(in In) {
				result = in
			},
		),
	)
	require.NoError(app.Err())
	app.RequireStart()
	assert.NotNil(result.AuthChain)
	app.RequireStop()
}

func TestProvideOptionalMiddleware(t *testing.T) {
	type In struct {
		fx.In
		AuthChain alice.Chain `name:"auth_chain"`
	}
	basic := EncodedBasicKeys{[]string{"dXNlcjpwYXNz"}}
	tests := []struct {
		desc string
		opts []fx.Option
	}{
		{
			desc: "basic auth, enforce",
			opts: []fx.Option{
				fx.Supply(basic),
				fx.Supply(basculechecks.CapabilitiesValidatorConfig{
					Type:            "enforce",
					Prefix:          "test",
					AcceptAllMethod: "all",
					EndpointBuckets: []string{"aaaa\\b", "bbbn/.*\\b"},
				}),
			},
		},
		{
			desc: "basic auth, monitor",
			opts: []fx.Option{
				fx.Supply(basic),
				fx.Supply(basculechecks.CapabilitiesValidatorConfig{
					Type:            "monitor",
					Prefix:          "test",
					AcceptAllMethod: "all",
					EndpointBuckets: []string{"aaaa\\b", "bbbn/.*\\b"},
				}),
			},
		},
		{
			desc: "no capability check",
			opts: []fx.Option{
				fx.Supply(basic),
				fx.Supply(basculechecks.CapabilitiesValidatorConfig{}),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			result := In{}
			app := fxtest.New(
				t,

				// supplying dependencies
				fx.Options(tc.opts...),
				fx.Supply(zaptest.NewLogger(t)),
				touchstone.Provide(),
				fx.Provide(
					fx.Annotated{
						Name: "default_key_id",
						Target: func() string {
							return "current"
						},
					},
				),
				// the parts we care about
				ProvideMetrics(),
				ProvideBasicAuth(),
				ProvideBearerTokenFactory(true),
				basculechecks.ProvideMetrics(),
				basculechecks.ProvideRegexCapabilitiesValidator(),
				ProvideBearerValidator(),
				ProvideServerChain(),

				fx.Invoke(
					func(in In) {
						result = in
					},
				),
			)
			require.NoError(app.Err())
			app.RequireStart()
			assert.NotNil(result.AuthChain)
			app.RequireStop()
		})
	}
}
