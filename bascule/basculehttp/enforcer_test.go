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

func TestEnforcer(t *testing.T) {
	e := NewEnforcer(
		WithNotFoundBehavior(Allow),
		WithELogger(func(_ context.Context) bascule.Logger { return nil }),
	)
	e2 := NewEnforcer(
		WithRules("jwt", bascule.Validators{bascule.CreateNonEmptyTypeCheck()}),
		WithELogger(func(_ context.Context) bascule.Logger {
			return bascule.Logger(log.NewJSONLogger(log.NewSyncWriter(os.Stdout)))
		}),
	)
	tests := []struct {
		description        string
		enforcer           func(http.Handler) http.Handler
		noAuth             bool
		auth               bascule.Authentication
		expectedStatusCode int
	}{
		{
			description: "Success",
			enforcer:    e2,
			auth: bascule.Authentication{
				Authorization: "jwt",
				Token:         bascule.NewToken("test", "", bascule.Attributes{}),
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			description:        "No Auth Error",
			enforcer:           e2,
			noAuth:             true,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			description:        "Forbid Error",
			enforcer:           e2,
			auth:               bascule.Authentication{Authorization: "test"},
			expectedStatusCode: http.StatusForbidden,
		},
		{
			description:        "Allow Success",
			enforcer:           e,
			auth:               bascule.Authentication{Authorization: "test"},
			expectedStatusCode: http.StatusOK,
		},
		{
			description: "Rule Check Error",
			enforcer:    e2,
			auth: bascule.Authentication{
				Authorization: "jwt",
				Token:         bascule.NewToken("", "", bascule.Attributes{}),
			},
			expectedStatusCode: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			handler := tc.enforcer(next)

			writer := httptest.NewRecorder()
			req := httptest.NewRequest("get", "/", nil)
			if !tc.noAuth {
				req = req.WithContext(bascule.WithAuthentication(context.Background(), tc.auth))
			}
			handler.ServeHTTP(writer, req)
			assert.Equal(tc.expectedStatusCode, writer.Code)
		})
	}
}
