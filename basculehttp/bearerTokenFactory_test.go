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
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/arrange"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/clortho"
	"go.uber.org/fx"
)

func TestBearerTokenFactory(t *testing.T) {
	parseFailErr := errors.New("parse fail test")
	resolveFailErr := errors.New("resolve fail test")
	tests := []struct {
		description   string
		value         string
		parseCalled   bool
		parseErr      error
		resolveCalled bool
		resolveErr    error
		claims        jwt.Claims
		validToken    bool
		expectedToken bascule.Token
		expectedErr   error
	}{
		{
			description:   "Success",
			value:         "abcd",
			parseCalled:   true,
			resolveCalled: true,
			claims: &bascule.ClaimsWithLeeway{
				MapClaims: jwt.MapClaims{jwtPrincipalKey: "test"},
			},
			validToken:    true,
			expectedToken: bascule.NewToken("jwt", "test", bascule.BasicAttributes{jwtPrincipalKey: "test"}),
			expectedErr:   nil,
		},
		{
			description: "Empty Value Error",
			value:       "",
			expectedErr: ErrEmptyValue,
		},
		{
			description: "Parse Failure Error",
			value:       "abcd",
			parseCalled: true,
			parseErr:    parseFailErr,
			expectedErr: parseFailErr,
		},
		{
			description:   "Resolve Key Error",
			value:         "abcd",
			parseCalled:   true,
			resolveCalled: true,
			resolveErr:    resolveFailErr,
			expectedErr:   resolveFailErr,
		},
		{
			description:   "Invalid Token Error",
			value:         "abcd",
			parseCalled:   true,
			resolveCalled: true,
			validToken:    false,
			expectedErr:   ErrInvalidToken,
		},
		{
			description:   "Convert to Claims Error",
			value:         "abcd",
			parseCalled:   true,
			resolveCalled: true,
			validToken:    true,
			expectedErr:   ErrUnexpectedClaims,
		},
		{
			description:   "Get Principal Error",
			value:         "abcd",
			parseCalled:   true,
			resolveCalled: true,
			validToken:    true,
			claims:        &bascule.ClaimsWithLeeway{},
			expectedErr:   ErrInvalidPrincipal,
		},
		{
			description:   "Non-string Principal Error",
			value:         "abcd",
			parseCalled:   true,
			resolveCalled: true,
			validToken:    true,
			claims: &bascule.ClaimsWithLeeway{
				MapClaims: jwt.MapClaims{jwtPrincipalKey: 55.0},
			},
			expectedErr: ErrInvalidPrincipal,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			r := new(MockResolver)
			p := new(mockParser)
			key := new(MockKey)
			if tc.parseCalled {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, tc.claims)
				token.Valid = tc.validToken
				p.On("ParseJWT", mock.Anything, mock.Anything, mock.Anything).Return(token, tc.parseErr).Once()
			}
			if tc.resolveCalled {
				r.On("Resolve", mock.Anything, mock.Anything).Return(key, tc.resolveErr).Once()
				if tc.resolveErr == nil {
					key.On("Public").Return(nil).Once()
				}
			}
			btf := BearerTokenFactory{
				DefaultKeyID: "default key id",
				Resolver:     r,
				Parser:       p,
			}
			req := httptest.NewRequest("get", "/", nil)
			token, err := btf.ParseAndValidate(context.Background(), req, "", tc.value)
			assert.Equal(tc.expectedToken, token)
			key.AssertExpectations(t)
			if tc.expectedErr == nil || err == nil {
				assert.Equal(tc.expectedErr, err)
			} else {
				assert.Contains(err.Error(), tc.expectedErr.Error())
			}
		})
	}
}

func TestProvideBearerTokenFactory(t *testing.T) {
	type In struct {
		fx.In
		Options []COption `group:"bascule_constructor_options"`
	}

	const yaml = `
good:
  key:
    factory:
      uri: "http://test:1111/keys/{keyId}"
    purpose: 0
    updateInterval: 604800000000000
`
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))

	tests := []struct {
		description    string
		key            string
		optional       bool
		optionExpected bool
		expectedErr    error
	}{
		{
			description:    "Success",
			key:            "good",
			optional:       false,
			optionExpected: true,
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
				fx.Provide(
					fx.Annotated{
						Name: "default_key_id",
						Target: func() string {
							return "default"
						},
					},
				),
				arrange.TestLogger(t),
				arrange.ForViper(v),
				ProvideBearerTokenFactory(tc.key, tc.optional),
				fx.Invoke(
					func(in In) {
						result = in
					},
				),
			)
			err := app.Err()
			if tc.expectedErr == nil {
				assert.NoError(err)
				assert.True(len(result.Options) == 1)
				if tc.optionExpected {
					require.NotNil(result.Options[0])
					return
				}
				return
			}
			assert.Nil(result.Options)
			require.Error(err)
			assert.True(strings.Contains(err.Error(), tc.expectedErr.Error()),
				fmt.Errorf("error [%v] doesn't contain error [%v]",
					err, tc.expectedErr),
			)
		})
	}
}

func TestProvideResolver(t *testing.T) {
	type In struct {
		fx.In
		R clortho.Resolver `name:"key_resolver"`
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

	goodResolver, err := clortho.NewResolver(clortho.WithKeyIDTemplate("good"))
	require.Nil(t, err)

	tests := []struct {
		description      string
		key              string
		optional         bool
		expectedResolver clortho.Resolver
		expectedErr      error
	}{
		{
			description:      "Success",
			key:              "good",
			optional:         false,
			expectedResolver: goodResolver,
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
