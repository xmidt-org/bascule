// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type testAttributes map[string]any

func (ta testAttributes) Get(key string) (v any, ok bool) {
	v, ok = ta[key]
	return
}

type AttributesTestSuite struct {
	suite.Suite
}

func (suite *AttributesTestSuite) testAttributesAccessor() AttributesAccessor {
	return testAttributes{
		"value":      123,
		"untypedNil": nil,
		"emptyMap":   map[string]any{},
		"nestedMap": map[string]any{
			"value": 123,
			"nestedMap": map[string]any{
				"value": 123,
			},
			"nestedAttributes": AttributesAccessor(testAttributes{
				"value": 123,
			}),
		},
		"nestedAttributes": AttributesAccessor(testAttributes{
			"value": 123,
			"nestedMap": map[string]any{
				"value": 123,
			},
			"nestedAttributes": AttributesAccessor(testAttributes{
				"value": 123,
			}),
		}),
	}
}

func (suite *AttributesTestSuite) TestGetAttribute() {
	testCases := []struct {
		keys          []string
		expectedValue int
		expectedOK    bool
	}{
		{
			keys: nil,
		},
		{
			keys: []string{"missing"},
		},
		{
			keys: []string{"untypedNil"},
		},
		{
			keys: []string{"untypedNil", "value"},
		},
		{
			keys:          []string{"value"},
			expectedValue: 123,
			expectedOK:    true,
		},
		{
			keys: []string{"emptyMap"},
		},
		{
			keys: []string{"emptyMap", "value"},
		},
		{
			keys: []string{"nestedMap"},
		},
		{
			keys: []string{"nestedMap", "missing"},
		},
		{
			keys:          []string{"nestedMap", "value"},
			expectedValue: 123,
			expectedOK:    true,
		},
		{
			keys: []string{"nestedMap", "nestedMap", "missing"},
		},
		{
			keys:          []string{"nestedMap", "nestedMap", "value"},
			expectedValue: 123,
			expectedOK:    true,
		},
		{
			keys:          []string{"nestedMap", "nestedAttributes", "value"},
			expectedValue: 123,
			expectedOK:    true,
		},
		{
			keys: []string{"nestedAttributes", "nestedMap", "missing"},
		},
		{
			keys:          []string{"nestedAttributes", "nestedMap", "value"},
			expectedValue: 123,
			expectedOK:    true,
		},
		{
			keys:          []string{"nestedAttributes", "nestedAttributes", "value"},
			expectedValue: 123,
			expectedOK:    true,
		},
	}

	for _, testCase := range testCases {
		suite.Run(fmt.Sprintf("%v", testCase.keys), func() {
			actual, ok := GetAttribute[int](suite.testAttributesAccessor(), testCase.keys...)
			suite.Equal(testCase.expectedValue, actual)
			suite.Equal(testCase.expectedOK, ok)
		})
	}
}

func TestAttributes(t *testing.T) {
	suite.Run(t, new(AttributesTestSuite))
}
