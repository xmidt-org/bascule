/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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

package key

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/arrange"
	"github.com/xmidt-org/webpa-common/resource"
	"go.uber.org/fx"
)

func TestBadURITemplates(t *testing.T) {
	assert := assert.New(t)

	badURITemplates := []string{
		"",
		"badscheme://foo/bar.pem",
		"http://badtemplate.com/{bad",
		"file:///etc/{too}/{many}/{parameters}",
		"http://missing.keyId.com/{someOtherName}",
	}

	for _, badURITemplate := range badURITemplates {
		t.Logf("badURITemplate: %s", badURITemplate)

		factory := ResolverFactory{
			Factory: resource.Factory{
				URI: badURITemplate,
			},
		}

		resolver, err := factory.NewResolver()
		assert.Nil(resolver)
		assert.NotNil(err)
	}
}

func TestResolverFactoryDefaultParser(t *testing.T) {
	assert := assert.New(t)

	parser := &MockParser{}
	resolverFactory := ResolverFactory{
		Factory: resource.Factory{
			URI: publicKeyFilePath,
		},
	}

	assert.Equal(DefaultParser, resolverFactory.parser())
	parser.AssertExpectations(t)
}

func TestResolverFactoryCustomParser(t *testing.T) {
	assert := assert.New(t)

	parser := &MockParser{}
	resolverFactory := ResolverFactory{
		Factory: resource.Factory{
			URI: publicKeyFilePath,
		},
		Parser: parser,
	}

	assert.Equal(parser, resolverFactory.parser())
	parser.AssertExpectations(t)
}

func TestProvideResolver(t *testing.T) {
	type In struct {
		fx.In
		R Resolver `name:"key_resolver"`
	}

	const yaml = `
good:
  factory:
    uri: "http://test:1111/keys/{keyId}"
  purpose: 0
  updateInterval: 604800000000000
`
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))

	f := &ResolverFactory{
		Factory: resource.Factory{
			URI: "http://test:1111/keys/{keyId}",
		},
		Purpose:        0,
		UpdateInterval: 604800000000000,
	}
	goodResolver, err := f.NewResolver()
	require.Nil(t, err)

	tests := []struct {
		description      string
		key              string
		optional         bool
		expectedResolver Resolver
		expectedErr      error
	}{
		{
			description:      "Success",
			key:              "good",
			optional:         false,
			expectedResolver: goodResolver,
		},
		{
			description: "Failure",
			key:         "bad",
			optional:    false,
			expectedErr: ErrNoResolverFactory,
		},
		{
			description: "Silent failure",
			key:         "bad",
			optional:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			result := In{}
			assert := assert.New(t)
			require := require.New(t)
			app := fx.New(
				arrange.TestLogger(t),
				arrange.ForViper(v),
				ProvideResolver(tc.key, tc.optional),
				fx.Invoke(
					func(in In) {
						result = in
					},
				),
			)
			err := app.Err()
			assert.Equal(tc.expectedResolver, result.R)
			if tc.expectedErr == nil {
				assert.NoError(err)
				return
			}
			require.Error(err)
			assert.True(strings.Contains(err.Error(), tc.expectedErr.Error()),
				fmt.Errorf("error [%v] doesn't contain error [%v]",
					err, tc.expectedErr),
			)
		})
	}
}
