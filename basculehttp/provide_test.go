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
	"strings"
	"testing"

	"github.com/justinas/alice"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/arrange"
	"github.com/xmidt-org/bascule/basculechecks"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
)

func TestProvideBearerMiddleware(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	const yaml = `
bearer:
  key:
    factory:
      uri: "http://test:1111/keys/{keyId}"
    purpose: 0
    updateInterval: 604800000000000
capabilities:
  endpoints:
    ".*/a/.*": "whatsup"
    ".*/b/.*": "nm"
  default: "eh"
`
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(v.ReadConfig(strings.NewReader(yaml)))
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
		arrange.LoggerFunc(l.Sugar().Infof),
		fx.Supply(l),
		arrange.ForViper(v),
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
		ProvideBasicAuth("basic"),
		ProvideBearerTokenFactory("bearer", false),
		basculechecks.ProvideMetrics(),
		basculechecks.ProvideCapabilitiesMapValidator("capabilities"),
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
	basicAuth := `
basic: ["dXNlcjpwYXNz"]
`
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
	for desc, yaml := range yamls {
		t.Run(desc, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			v := viper.New()
			v.SetConfigType("yaml")
			require.NoError(v.ReadConfig(strings.NewReader(yaml)))
			l, err := zap.NewDevelopment()
			require.NoError(err)

			result := In{}
			app := fxtest.New(
				t,

				// supplying dependencies
				arrange.LoggerFunc(l.Sugar().Infof),
				fx.Supply(l),
				arrange.ForViper(v),
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
				ProvideBearerTokenFactory("bearer", true),
				basculechecks.ProvideMetrics(),
				basculechecks.ProvideRegexCapabilitiesValidator("capabilities"),
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
