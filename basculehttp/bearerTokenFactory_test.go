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
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/key"
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
			r := new(key.MockResolver)
			p := new(mockParser)
			pair := new(key.MockPair)
			if tc.parseCalled {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, tc.claims)
				token.Valid = tc.validToken
				p.On("ParseJWT", mock.Anything, mock.Anything, mock.Anything).Return(token, tc.parseErr).Once()
			}
			if tc.resolveCalled {
				r.On("ResolveKey", mock.Anything, mock.Anything).Return(pair, tc.resolveErr).Once()
				if tc.resolveErr == nil {
					pair.On("Public").Return(nil).Once()
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
			if tc.expectedErr == nil || err == nil {
				assert.Equal(tc.expectedErr, err)
			} else {
				assert.Contains(err.Error(), tc.expectedErr.Error())
			}
		})
	}
}
