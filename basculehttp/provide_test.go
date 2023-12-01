// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculechecks"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/sallust"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
)

func TestProvideBearerMiddleware(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	l, err := zap.NewDevelopment()
	require.NoError(err)

	type In struct {
		fx.In
		AuthChain alice.Chain `name:"auth_chain"`
	}
	result := In{}
	app := fxtest.New(
		t,

		// supplying dependencies
		fx.Supply(l),
		touchstone.Provide(),
		fx.Provide(
			func() (c sallust.Config) {
				return sallust.Config{}
			},
			func() (c basculechecks.CapabilitiesMapConfig) {
				return basculechecks.CapabilitiesMapConfig{
					Endpoints: map[string]string{
						".*/a/.*": "whatsup",
						".*/b/.*": "nm",
					},
					Default: "eh",
				}
			},
			fx.Annotated{
				Name: "default_key_id",
				Target: func() string {
					return "default"
				},
			},
			fx.Annotated{
				Name: "key_resolver",
				Target: func() clortho.Resolver {
					r := new(MockResolver)
					return r
				},
			},
			fx.Annotated{
				Name: "parser",
				Target: func() bascule.JWTParser {
					p := new(mockParser)
					return p
				},
			},
			fx.Annotated{
				Name: "jwt_leeway",
				Target: func() bascule.Leeway {
					return bascule.Leeway{EXP: 5}
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
	t.Run("no capability check or bearer token factory or basic auth", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		l, err := zap.NewDevelopment()
		require.NoError(err)

		result := In{}
		app := fxtest.New(
			t,

			// supplying dependencies
			fx.Supply(l),
			touchstone.Provide(),
			fx.Provide(
				func() (c sallust.Config) {
					return sallust.Config{}
				},
				fx.Annotated{
					Name: "encoded_basic_auths",
					Target: func() EncodedBasicKeys {
						return EncodedBasicKeys{Basic: []string{"dXNlcjpwYXNz", "dXNlcjpwYXNz", "dXNlcjpwYXNz"}}
					},
				},
				func() (c basculechecks.CapabilitiesValidatorConfig) {
					return basculechecks.CapabilitiesValidatorConfig{
						Type:            "enforce",
						EndpointBuckets: []string{"abc", "def", `\M`, "adbecf"},
					}
				},
			),
			// the parts we care about
			ProvideMetrics(),
			ProvideBasicAuth(""),
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
