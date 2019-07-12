package basculehttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
)

func TestBasicTokenFactory(t *testing.T) {
	btf := BasicTokenFactory(map[string]string{
		"user": "pass",
		"test": "valid",
	})
	tests := []struct {
		description   string
		value         string
		expectedToken bascule.Token
		expectedErr   error
	}{
		{
			description:   "Sucess",
			value:         base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedToken: bascule.NewToken("basic", "user", bascule.Attributes{}),
		},
		{
			description: "Can't Decode Error",
			value:       "abcdef",
			expectedErr: errors.New("illegal base64 data"),
		},
		{
			description: "Malformed Value Error",
			value:       base64.StdEncoding.EncodeToString([]byte("abcdef")),
			expectedErr: ErrorMalformedValue,
		},
		{
			description: "Key Not in Map Error",
			value:       base64.StdEncoding.EncodeToString([]byte("u:p")),
			expectedErr: ErrorNotInMap,
		},
		{
			description: "Invalid Password Error",
			value:       base64.StdEncoding.EncodeToString([]byte("user:p")),
			expectedErr: ErrorInvalidPassword,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
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
