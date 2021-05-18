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

package basculechecks

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
)

func TestCapabilitiesMapCheck(t *testing.T) {
	goodDefault := ConstEndpointCheck("default checker")
	checkersMap := map[string]EndpointChecker{
		"a":        ConstEndpointCheck("meh"),
		"bcedef":   ConstEndpointCheck("yay"),
		"all":      ConstEndpointCheck("good"),
		"fallback": nil,
	}
	cm := CapabilitiesMap{
		Checkers:       checkersMap,
		DefaultChecker: goodDefault,
	}
	nilCM := CapabilitiesMap{}
	goodCapabilities := []string{
		"test",
		"",
		"yay",
		"...",
	}
	goodToken := bascule.NewToken("test", "princ",
		bascule.NewAttributes(map[string]interface{}{CapabilityKey: goodCapabilities}))
	defaultCapabilities := []string{
		"test",
		"",
		"default checker",
		"...",
	}
	defaultToken := bascule.NewToken("test", "princ",
		bascule.NewAttributes(map[string]interface{}{CapabilityKey: defaultCapabilities}))
	badToken := bascule.NewToken("", "", nil)
	tests := []struct {
		description string
		cm          CapabilitiesMap
		token       bascule.Token
		includeURL  bool
		endpoint    string
		expectedErr error
	}{
		{
			description: "Success",
			cm:          cm,
			token:       goodToken,
			includeURL:  true,
			endpoint:    "bcedef",
		},
		{
			description: "Success Not in Map",
			cm:          cm,
			token:       defaultToken,
			includeURL:  true,
			endpoint:    "b",
		},
		{
			description: "Success Nil Map Value",
			cm:          cm,
			token:       defaultToken,
			includeURL:  true,
			endpoint:    "fallback",
		},
		{
			description: "No Match Error",
			cm:          cm,
			token:       goodToken,
			includeURL:  true,
			endpoint:    "b",
			expectedErr: ErrNoValidCapabilityFound,
		},
		{
			description: "No Match with Default Checker Error",
			cm:          cm,
			token:       defaultToken,
			includeURL:  true,
			endpoint:    "bcedef",
			expectedErr: ErrNoValidCapabilityFound,
		},
		{
			description: "No Match Nil Default Checker Error",
			cm:          nilCM,
			token:       defaultToken,
			includeURL:  true,
			endpoint:    "bcedef",
			expectedErr: ErrNoValidCapabilityFound,
		},
		{
			description: "No Token Error",
			cm:          cm,
			token:       nil,
			includeURL:  true,
			expectedErr: ErrNoToken,
		},
		{
			description: "No Request URL Error",
			cm:          cm,
			token:       goodToken,
			includeURL:  false,
			expectedErr: ErrNoURL,
		},
		{
			description: "Empty Endpoint Error",
			cm:          cm,
			token:       goodToken,
			includeURL:  true,
			endpoint:    "",
			expectedErr: ErrEmptyEndpoint,
		},
		{
			description: "Get Capabilities Error",
			cm:          cm,
			token:       badToken,
			includeURL:  true,
			endpoint:    "b",
			expectedErr: ErrNilAttributes,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			auth := bascule.Authentication{
				Token: tc.token,
			}
			if tc.includeURL {
				goodURL, err := url.Parse("/test")
				require.Nil(err)
				auth.Request = bascule.Request{
					URL:    goodURL,
					Method: "GET",
				}
			}
			err := tc.cm.CheckAuthentication(auth, ParsedValues{Endpoint: tc.endpoint})
			if tc.expectedErr == nil {
				assert.NoError(err)
				return
			}
			assert.True(errors.Is(err, tc.expectedErr),
				fmt.Errorf("error [%v] doesn't contain error [%v] in its err chain",
					err, tc.expectedErr),
			)
			// every error should be a reasoner.
			var r Reasoner
			assert.True(errors.As(err, &r), "expected error to be a Reasoner")
		})
	}
}

func TestNewCapabilitiesMap(t *testing.T) {
	a := ".*"
	b := "aaaaa+"
	c1 := "yup"
	c2 := "nope"
	es := map[string]string{a: c1, b: c2}
	m := map[string]EndpointChecker{
		a: ConstEndpointCheck(c1),
		b: ConstEndpointCheck(c2),
	}

	tests := []struct {
		description     string
		config          CapabilitiesMapConfig
		expectedChecker CapabilitiesChecker
		expectedErr     error
	}{
		{
			description: "Success",
			config: CapabilitiesMapConfig{
				Endpoints: es,
			},
			expectedChecker: CapabilitiesMap{
				Checkers: m,
			},
		},
		{
			description: "Success with default",
			config: CapabilitiesMapConfig{
				Endpoints: es,
				Default:   "pls",
			},
			expectedChecker: CapabilitiesMap{
				Checkers:       m,
				DefaultChecker: ConstEndpointCheck("pls"),
			},
		},
		{
			description: "Regex fail",
			config: CapabilitiesMapConfig{
				Endpoints: map[string]string{
					`\m\n\b\v`: "test",
				},
			},
			expectedErr: errRegexCompileFail,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			c, err := NewCapabilitiesMap(tc.config)
			if tc.expectedErr != nil {
				assert.Empty(c)
				require.Error(t, err)
				assert.True(errors.Is(err, tc.expectedErr),
					fmt.Errorf("error [%v] doesn't contain error [%v] in its err chain",
						err, tc.expectedErr),
				)
				return
			}
			assert.NoError(err)
			assert.NotEmpty(c)
			assert.Equal(tc.expectedChecker, c.Checker)
			assert.NotNil(c.Options)
		})
	}
}
