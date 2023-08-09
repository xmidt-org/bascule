// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
	"go.uber.org/zap/zaptest"
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
			description:   "Success",
			value:         base64.StdEncoding.EncodeToString([]byte("user:pass")),
			expectedToken: bascule.NewToken("basic", "user", bascule.NewAttributes(map[string]interface{}{})),
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
			expectedErr: ErrorPrincipalNotFound,
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

func TestNewBasicTokenFactoryFromList(t *testing.T) {
	goodKey := `dXNlcjpwYXNz`
	badKeyDecode := `dXNlcjpwYXN\\\`
	badKeyNoColon := `dXNlcnBhc3M=`
	goodMap := map[string]string{"user": "pass"}
	emptyMap := map[string]string{}

	tests := []struct {
		description        string
		keyList            []string
		expectedDecodedMap BasicTokenFactory
		expectedErr        error
	}{
		{
			description:        "Success",
			keyList:            []string{goodKey},
			expectedDecodedMap: goodMap,
		},
		{
			description:        "Success With Errors",
			keyList:            []string{goodKey, badKeyDecode, badKeyNoColon},
			expectedDecodedMap: goodMap,
			expectedErr:        errors.New("multiple errors"),
		},
		{
			description:        "Decode Error",
			keyList:            []string{badKeyDecode},
			expectedDecodedMap: emptyMap,
			expectedErr:        errors.New("failed to base64-decode basic auth key"),
		},
		{
			description:        "Success",
			keyList:            []string{badKeyNoColon},
			expectedDecodedMap: emptyMap,
			expectedErr:        errors.New("malformed"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			m, err := NewBasicTokenFactoryFromList(tc.keyList)
			assert.Equal(tc.expectedDecodedMap, m)
			if tc.expectedErr == nil || err == nil {
				assert.Equal(tc.expectedErr, err)
			} else {
				assert.Contains(err.Error(), tc.expectedErr.Error())
			}
		})
	}
}

func TestProvideBasicTokenFactory(t *testing.T) {
	type In struct {
		fx.In
		Options []COption `group:"bascule_constructor_options"`
	}

	tests := []struct {
		description    string
		opt            fx.Option
		optionExpected bool
		expectedErr    error
	}{
		{
			description: "Success",
			opt: fx.Supply(EncodedBasicKeys{
				Basic: []string{"dXNlcjpwYXNz", "dXNlcjpwYXNz", "dXNlcjpwYXNz"},
			}),
			optionExpected: true,
		},
		{
			description: "Disabled success",
		},
		{
			description: "Failure",
			opt:         fx.Supply(EncodedBasicKeys{Basic: []string{"AAAAAAAA"}}),
			expectedErr: errors.New("malformed"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			result := In{}
			assert := assert.New(t)
			require := require.New(t)

			if tc.opt == nil {
				tc.opt = fx.Supply(EncodedBasicKeys{})
			}
			app := fx.New(
				fx.Supply(zaptest.NewLogger(t)),
				ProvideBasicTokenFactory(),
				tc.opt,
				fx.Invoke(
					func(in In) {
						result = in
					},
				),
			)
			err := app.Err()
			if tc.expectedErr == nil {
				assert.NoError(err)
				require.True(len(result.Options) == 1)
				if tc.optionExpected {
					assert.NotNil(result.Options[0])
					return
				}
				assert.Nil(result.Options[0])
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
