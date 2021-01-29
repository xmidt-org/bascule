/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
)

func TestConstructor(t *testing.T) {
	testHeader := "test header"
	testDelimiter := "="

	c := NewConstructor(
		WithHeaderName(testHeader),
		WithHeaderDelimiter(testDelimiter),
		WithTokenFactory("Basic", BasicTokenFactory{"codex": "codex"}),
		WithCLogger(func(_ context.Context) bascule.Logger {
			return bascule.Logger(log.NewJSONLogger(log.NewSyncWriter(os.Stdout)))
		}),
		WithParseURLFunc(CreateRemovePrefixURLFunc("/test", DefaultParseURLFunc)),
		WithCErrorResponseFunc(DefaultOnErrorResponse),
	)
	c2 := NewConstructor(
		WithHeaderName(""),
		WithHeaderDelimiter(""),
		WithCLogger(func(_ context.Context) bascule.Logger { return nil }),
	)
	tests := []struct {
		description        string
		constructor        func(http.Handler) http.Handler
		requestHeaderKey   string
		requestHeaderValue string
		expectedStatusCode int
		endpoint           string
	}{
		{
			description:        "Success",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "Basic=Y29kZXg6Y29kZXg=",
			expectedStatusCode: http.StatusOK,
			endpoint:           "/test",
		},
		{
			description:        "URL Parsing Error",
			constructor:        c,
			endpoint:           "/blah",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			description:        "No Authorization Header Error",
			constructor:        c2,
			requestHeaderKey:   DefaultHeaderName,
			requestHeaderValue: "",
			expectedStatusCode: http.StatusForbidden,
			endpoint:           "/",
		},
		{
			description:        "No Space in Auth Header Error",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "abcd",
			expectedStatusCode: http.StatusBadRequest,
			endpoint:           "/test",
		},
		{
			description:        "Key Not Supported Error",
			constructor:        c2,
			requestHeaderKey:   DefaultHeaderName,
			requestHeaderValue: "abcd ",
			expectedStatusCode: http.StatusForbidden,
			endpoint:           "/test",
		},
		{
			description:        "Key Wrong Case Error",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "bAsIc=Y29kZXg6Y29kZXg=",
			expectedStatusCode: http.StatusForbidden,
			endpoint:           "/test",
		},
		{
			description:        "Parse and Validate Error",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "Basic=AFJDK",
			expectedStatusCode: http.StatusForbidden,
			endpoint:           "/test",
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			handler := tc.constructor(next)

			writer := httptest.NewRecorder()
			req := httptest.NewRequest("get", tc.endpoint, nil)
			req.Header.Add(tc.requestHeaderKey, tc.requestHeaderValue)
			handler.ServeHTTP(writer, req)
			assert.Equal(tc.expectedStatusCode, writer.Code)
		})
	}
}
