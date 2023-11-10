// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/sallust"
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
			key := new(mockKey)
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

	t.Run("Success", func(t *testing.T) {
		result := In{}
		require := require.New(t)
		app := fx.New(
			fx.Provide(
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
				func() (c sallust.Config) {
					return sallust.Config{}
				},
			),
			sallust.WithLogger(),
			ProvideBearerTokenFactory(false),
			fx.Invoke(
				func(in In) {
					result = in
				},
			),
		)
		err := app.Err()
		require.NoError(err)
		require.NotEmpty(result.Options)
		require.NotNil(result.Options[0])
	})
}

func TestOptionalProvideBearerTokenFactory(t *testing.T) {
	type In struct {
		fx.In
		Options []COption `group:"bascule_constructor_options"`
	}

	t.Run("Silent failure", func(t *testing.T) {
		result := In{}
		require := require.New(t)
		app := fx.New(
			fx.Provide(
				func() (c sallust.Config) {
					return sallust.Config{}
				},
			),
			sallust.WithLogger(),
			ProvideBearerTokenFactory(true),
			fx.Invoke(
				func(in In) {
					result = in
				},
			),
		)
		err := app.Err()
		require.NoError(err)
		require.NotEmpty(result.Options)
		require.Nil(result.Options[0])
	})
}
