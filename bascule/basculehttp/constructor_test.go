package basculehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Comcast/comcast-bascule/bascule"
	"github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"
)

func TestConstructor(t *testing.T) {
	testHeader := "test header"
	c := NewConstructor(
		WithHeaderName(testHeader),
		WithTokenFactory("Basic", BasicTokenFactory{"codex": "codex"}),
		WithCLogger(func(_ context.Context) bascule.Logger {
			return bascule.Logger(log.NewJSONLogger(log.NewSyncWriter(os.Stdout)))
		}),
	)
	c2 := NewConstructor(
		WithHeaderName(""),
		WithCLogger(func(_ context.Context) bascule.Logger { return nil }),
	)
	tests := []struct {
		description        string
		constructor        func(http.Handler) http.Handler
		requestHeaderKey   string
		requestHeaderValue string
		expectedStatusCode int
	}{
		{
			description:        "Success",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "Basic Y29kZXg6Y29kZXg=",
			expectedStatusCode: http.StatusOK,
		},
		{
			description:        "No Authorization Header Error",
			constructor:        c2,
			requestHeaderKey:   DefaultHeaderName,
			requestHeaderValue: "",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			description:        "No Space in Auth Header Error",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "abcd",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			description:        "Key Not Supported Error",
			constructor:        c2,
			requestHeaderKey:   DefaultHeaderName,
			requestHeaderValue: "abcd ",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			description:        "Parse and Validate Error",
			constructor:        c,
			requestHeaderKey:   testHeader,
			requestHeaderValue: "Basic AFJDK",
			expectedStatusCode: http.StatusUnauthorized,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			handler := tc.constructor(next)

			writer := httptest.NewRecorder()
			req := httptest.NewRequest("get", "/", nil)
			req.Header.Add(tc.requestHeaderKey, tc.requestHeaderValue)
			handler.ServeHTTP(writer, req)
			assert.Equal(tc.expectedStatusCode, writer.Code)
		})
	}
}
