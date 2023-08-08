// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculechecks"
	"github.com/xmidt-org/sallust"
)

func TestEnforcer(t *testing.T) {
	e := NewEnforcer(
		WithNotFoundBehavior(Allow),
		WithELogger(sallust.Get),
	)
	e2 := NewEnforcer(
		WithRules("jwt", bascule.Validators{basculechecks.NonEmptyType()}),
		WithELogger(sallust.Get),
		WithEErrorResponseFunc(DefaultOnErrorResponse),
	)
	emptyAttributes := bascule.NewAttributes(map[string]interface{}{})
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
				Token:         bascule.NewToken("test", "", emptyAttributes),
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
				Token:         bascule.NewToken("", "", emptyAttributes),
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
