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
