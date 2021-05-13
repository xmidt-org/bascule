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

//TODO: fix this test
// func TestBearerTokenFactory(t *testing.T) {
// 	parseFailErr := errors.New("parse fail test")
// 	resolveFailErr := errors.New("resolve fail test")
// 	validateFailErr := errors.New("validate fail test")
// 	tests := []struct {
// 		description     string
// 		value           string
// 		parseCalled     bool
// 		parseErr        error
// 		protectedCalled bool
// 		protectedHeader jose.Protected
// 		resolveCalled   bool
// 		resolveErr      error
// 		validateCalled  bool
// 		validateErr     error
// 		payloadCalled   bool
// 		payloadClaims   interface{}
// 		payloadOK       bool
// 		expectedToken   bascule.Token
// 		expectedErr     error
// 	}{
// 		{
// 			description:     "Success",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected(map[string]interface{}{"alg": "HS256"}),
// 			resolveCalled:   true,
// 			validateCalled:  true,
// 			payloadCalled:   true,
// 			payloadClaims:   jws.Claims(map[string]interface{}{jwtPrincipalKey: "test"}),
// 			payloadOK:       true,
// 			expectedToken:   bascule.NewToken("jwt", "test", bascule.Attributes{jwtPrincipalKey: "test"}),
// 			expectedErr:     nil,
// 		},
// 		{
// 			description: "Empty Value Error",
// 			value:       "",
// 			expectedErr: errors.New("empty value"),
// 		},
// 		{
// 			description: "Parse Failure Error",
// 			value:       "abcd",
// 			parseCalled: true,
// 			parseErr:    parseFailErr,
// 			expectedErr: parseFailErr,
// 		},
// 		{
// 			description:     "No Protected Header Error",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected{},
// 			expectedErr:     ErrorNoProtectedHeader,
// 		},
// 		{
// 			description:     "No Signing Method Error",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected(map[string]interface{}{"alg": "abcd"}),
// 			expectedErr:     ErrorNoSigningMethod,
// 		},
// 		{
// 			description:     "Resolve Key Error",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected(map[string]interface{}{"alg": "HS256"}),
// 			resolveCalled:   true,
// 			resolveErr:      resolveFailErr,
// 			expectedErr:     resolveFailErr,
// 		},
// 		{
// 			description:     "Validate Error",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected(map[string]interface{}{"alg": "HS256"}),
// 			resolveCalled:   true,
// 			validateCalled:  true,
// 			validateErr:     validateFailErr,
// 			expectedErr:     validateFailErr,
// 		},
// 		{
// 			description:     "Convert to Claims Error",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected(map[string]interface{}{"alg": "HS256"}),
// 			resolveCalled:   true,
// 			validateCalled:  true,
// 			payloadCalled:   true,
// 			payloadClaims:   55555,
// 			payloadOK:       false,
// 			expectedErr:     ErrorUnexpectedPayload,
// 		},
// 		{
// 			description:     "Payload Principal Error",
// 			value:           "abcd",
// 			parseCalled:     true,
// 			protectedCalled: true,
// 			protectedHeader: jose.Protected(map[string]interface{}{"alg": "HS256"}),
// 			resolveCalled:   true,
// 			validateCalled:  true,
// 			payloadCalled:   true,
// 			payloadClaims:   jws.Claims(map[string]interface{}{"test": "test"}),
// 			payloadOK:       true,
// 			expectedErr:     ErrorUnexpectedPrincipal,
// 		},
// 	}
// 	for _, tc := range tests {
// 		t.Run(tc.description, func(t *testing.T) {
// 			assert := assert.New(t)
// 			r := new(key.MockResolver)
// 			p := new(mockJWSParser)
// 			jwsToken := new(mockJWS)
// 			pair := new(key.MockPair)
// 			if tc.parseCalled {
// 				p.On("ParseJWS", mock.Anything).Return(jwsToken, tc.parseErr).Once()
// 			}
// 			if tc.protectedCalled {
// 				jwsToken.On("Protected").Return(tc.protectedHeader).Once()
// 			}
// 			if tc.resolveCalled {
// 				r.On("ResolveKey", mock.Anything, mock.Anything).Return(pair, tc.resolveErr).Once()
// 			}
// 			if tc.validateCalled {
// 				jwsToken.On("Verify", mock.Anything, mock.Anything).Return(tc.validateErr).Once()
// 				pair.On("Public").Return(nil).Once()
// 			}
// 			if tc.payloadCalled {
// 				jwsToken.On("Payload").Return(tc.payloadClaims, tc.payloadOK).Once()
// 			}
// 			btf := BearerTokenFactory{
// 				DefaultKeyId: "default key id",
// 				Resolver:     r,
// 				Parser:       p,
// 			}
// 			req := httptest.NewRequest("get", "/", nil)
// 			token, err := btf.ParseAndValidate(context.Background(), req, "", tc.value)
// 			assert.Equal(tc.expectedToken, token)
// 			if tc.expectedErr == nil || err == nil {
// 				assert.Equal(tc.expectedErr, err)
// 			} else {
// 				assert.Contains(err.Error(), tc.expectedErr.Error())
// 			}
// 		})
// 	}
// }
