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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestGetZapLogger(t *testing.T) {
	l := zap.NewNop()
	f := getZapLogger(func(_ context.Context) *zap.Logger {
		return l
	})
	result := f(context.Background())
	assert.NotNil(t, result)
	assert.NotPanics(t, func() {
		result.Log("msg", "testing", "error", "nope", "level", "debug")
	})
}

func TestSanitizeHeaders(t *testing.T) {
	testCases := []struct {
		Description string
		Input       http.Header
		Expected    http.Header
	}{
		{
			Description: "Filtered",
			Input:       http.Header{"Authorization": []string{"Basic xyz"}, "HeaderA": []string{"x"}},
			Expected:    http.Header{"HeaderA": []string{"x"}, "Authorization-Type": []string{"Basic"}},
		},
		{
			Description: "Handled human error",
			Input:       http.Header{"Authorization": []string{"BasicXYZ"}, "HeaderB": []string{"y"}},
			Expected:    http.Header{"HeaderB": []string{"y"}},
		},
		{
			Description: "Not a perfect system",
			Input:       http.Header{"Authorization": []string{"MySecret IWantToLeakIt"}},
			Expected:    http.Header{"Authorization-Type": []string{"MySecret"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			assert := assert.New(t)
			actual := sanitizeHeaders(tc.Input)
			assert.Equal(tc.Expected, actual)
		})

	}
}