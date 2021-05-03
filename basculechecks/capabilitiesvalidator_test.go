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
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
)

var _ CapabilitiesChecker = CapabilitiesValidator{}

func TestCapabilitiesValidatorCheck(t *testing.T) {
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}
	goodURL, err := url.Parse("/test")
	require.Nil(t, err)
	goodRequest := bascule.Request{
		URL:    goodURL,
		Method: "GET",
	}
	tests := []struct {
		description  string
		includeAuth  bool
		includeToken bool
		errorOut     bool
		errExpected  bool
	}{
		{
			description:  "Success",
			includeAuth:  true,
			includeToken: true,
			errorOut:     true,
		},
		{
			description: "No Auth Error",
			errorOut:    true,
			errExpected: true,
		},
		{
			description: "No Auth Suppressed Error",
		},
		{
			description: "Check Error",
			includeAuth: true,
			errorOut:    true,
			errExpected: true,
		},
		{
			description: "Check Suppressed Error",
			includeAuth: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			ctx := context.Background()
			auth := bascule.Authentication{
				Request: goodRequest,
			}
			if tc.includeToken {
				auth.Token = bascule.NewToken("test", "princ",
					bascule.NewAttributes(map[string]interface{}{CapabilityKey: capabilities}))
			}
			if tc.includeAuth {
				ctx = bascule.WithAuthentication(ctx, auth)
			}
			c := CapabilitiesValidator{
				Checker:  ConstEndpointCheck("it's a match"),
				ErrorOut: tc.errorOut,
			}
			err := c.Check(ctx, bascule.NewToken("", "", nil))
			if tc.errExpected {
				assert.NotNil(err)
				return
			}
			assert.Nil(err)
		})
	}
}

func TestCapabilitiesValidatorCheckAuthentication(t *testing.T) {
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}
	pv := ParsedValues{}
	tests := []struct {
		description       string
		includeToken      bool
		includeMethod     bool
		includeAttributes bool
		includeURL        bool
		checker           EndpointChecker
		expectedReason    string
		expectedErr       error
	}{
		{
			description:       "Success",
			includeMethod:     true,
			includeAttributes: true,
			includeURL:        true,
			checker:           ConstEndpointCheck("it's a match"),
			expectedErr:       nil,
		},
		{
			description:    "No Token Error",
			expectedReason: MissingValues,
			expectedErr:    ErrNoToken,
		},
		{
			description:    "No Method Error",
			includeToken:   true,
			expectedReason: MissingValues,
			expectedErr:    ErrNoMethod,
		},
		{
			description:    "Get Capabilities Error",
			includeToken:   true,
			includeMethod:  true,
			expectedReason: MissingValues,
			expectedErr:    ErrNilAttributes,
		},
		{
			description:       "No URL Error",
			includeAttributes: true,
			includeMethod:     true,
			expectedReason:    MissingValues,
			expectedErr:       ErrNoURL,
		},
		{
			description:       "Check Capabilities Error",
			includeAttributes: true,
			includeMethod:     true,
			includeURL:        true,
			checker:           AlwaysEndpointCheck(false),
			expectedReason:    NoCapabilitiesMatch,
			expectedErr:       ErrNoValidCapabilityFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			c := CapabilitiesValidator{
				Checker: tc.checker,
			}
			a := bascule.Authentication{}
			if tc.includeToken {
				a.Token = bascule.NewToken("", "", nil)
			}
			if tc.includeAttributes {
				a.Token = bascule.NewToken("test", "princ",
					bascule.NewAttributes(map[string]interface{}{CapabilityKey: capabilities}))
			}
			if tc.includeURL {
				goodURL, err := url.Parse("/test")
				require.Nil(err)
				a.Request = bascule.Request{
					URL: goodURL,
				}
			}
			if tc.includeMethod {
				a.Request.Method = "GET"
			}
			err := c.CheckAuthentication(a, pv)
			if tc.expectedReason != "" {
				var r Reasoner
				if assert.True(errors.As(err, &r)) {
					assert.Equal(tc.expectedReason, r.Reason())
				}
			}
			if err == nil || tc.expectedErr == nil {
				assert.Equal(tc.expectedErr, err)
				return
			}
			assert.Contains(err.Error(), tc.expectedErr.Error())
		})
	}
}

func TestCheckCapabilities(t *testing.T) {
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}

	tests := []struct {
		description    string
		goodCapability string
		expectedErr    error
	}{
		{
			description:    "Success",
			goodCapability: "it's a match",
		},
		{
			description: "No Capability Found Error",
			expectedErr: ErrNoValidCapabilityFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			c := CapabilitiesValidator{
				Checker: ConstEndpointCheck(tc.goodCapability),
			}
			err := c.checkCapabilities(capabilities, "", "")
			if err == nil || tc.expectedErr == nil {
				assert.Equal(tc.expectedErr, err)
				return
			}
			assert.Contains(err.Error(), tc.expectedErr.Error())
		})
	}
}

func TestGetCapabilities(t *testing.T) {
	goodKeyVal := []string{"cap1", "cap2"}
	emptyVal := []string{}
	tests := []struct {
		description      string
		nilAttributes    bool
		missingAttribute bool
		keyValue         interface{}
		expectedVals     []string
		expectedErr      error
	}{
		{
			description:  "Success",
			keyValue:     goodKeyVal,
			expectedVals: goodKeyVal,
			expectedErr:  nil,
		},
		{
			description:   "Nil Attributes Error",
			nilAttributes: true,
			expectedVals:  emptyVal,
			expectedErr:   ErrNilAttributes,
		},
		{
			description:      "No Attribute Error",
			missingAttribute: true,
			expectedVals:     emptyVal,
			expectedErr:      ErrGettingCapabilities,
		},
		{
			description:  "Nil Capabilities Error",
			keyValue:     nil,
			expectedVals: emptyVal,
			expectedErr:  ErrCapabilityNotStringSlice,
		},
		{
			description:  "Non List Capabilities Error",
			keyValue:     struct{ string }{"abcd"},
			expectedVals: emptyVal,
			expectedErr:  ErrCapabilityNotStringSlice,
		},
		{
			description:  "Non String List Capabilities Error",
			keyValue:     []int{0, 1, 2},
			expectedVals: emptyVal,
			expectedErr:  ErrCapabilityNotStringSlice,
		},
		{
			description:  "Empty Capabilities Error",
			keyValue:     emptyVal,
			expectedVals: emptyVal,
			expectedErr:  ErrNoVals,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			m := map[string]interface{}{CapabilityKey: tc.keyValue}
			if tc.missingAttribute {
				m = map[string]interface{}{}
			}
			attributes := bascule.NewAttributes(m)
			if tc.nilAttributes {
				attributes = nil
			}
			vals, err := getCapabilities(attributes)
			assert.Equal(tc.expectedVals, vals)
			if tc.expectedErr == nil {
				assert.NoError(err)
				return
			}
			assert.True(errors.Is(err, tc.expectedErr))
			// every error should be a reasoner.
			var r Reasoner
			assert.True(errors.As(err, &r))
		})
	}
}
