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
	//basicAuth := EncodedBasicKeys{[]string{"dXNlcjpwYXNz"}}
	// nolint:gosec
	/*
	   	bearerAuth := `
	   bearer:
	     key:
	       factory:
	         uri: "http://test:1111/keys/{keyId}"
	       purpose: 0
	       updateInterval: 604800000000000
	   `
	   	var yamls = map[string]string{
	   		"everything included": basicAuth + bearerAuth + `
	   capabilities:
	     type: "enforce"
	     prefix: "test"
	     acceptAllMethod: "all"
	     endpointBuckets:
	        - "aaaa\\b"
	        - "bbbn/.*\\b"
	   `,
	   		"capabilities monitoring": basicAuth + bearerAuth + `
	   capabilities:
	     type: "monitor"
	     prefix: "test"
	     acceptAllMethod: "all"
	     endpointBuckets:
	       - "aaaa\\b"
	       - "bbbn/.*\\b"
	   `,
	   		"no capability check": basicAuth + bearerAuth,
	   		"basic only":          basicAuth,
	   		"bearer only":         bearerAuth,
	   		"empty config":        ``,
	   	}
	*/

	tests := []struct {
		desc  string
		basic *EncodedBasicKeys
	}{
		{
			desc: "basic auth",
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
