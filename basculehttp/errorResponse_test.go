// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultOnErrorHTTPResponse(t *testing.T) {
	tcs := []struct {
		Description          string
		Reason               ErrorResponseReason
		ExpectAuthTypeHeader bool
		ExpectedCode         int
	}{
		{
			Description:          "MissingHeader",
			Reason:               MissingHeader,
			ExpectedCode:         401,
			ExpectAuthTypeHeader: true,
		},
		{
			Description:          "InvalidHeader",
			Reason:               InvalidHeader,
			ExpectedCode:         401,
			ExpectAuthTypeHeader: true,
		},
		{
			Description:          "KeyNotSupported",
			Reason:               KeyNotSupported,
			ExpectedCode:         401,
			ExpectAuthTypeHeader: true,
		},
		{
			Description:          "ParseFailed",
			Reason:               ParseFailed,
			ExpectedCode:         401,
			ExpectAuthTypeHeader: true,
		},
		{
			Description:          "GetURLFailed",
			Reason:               GetURLFailed,
			ExpectedCode:         401,
			ExpectAuthTypeHeader: true,
		},
		{
			Description:          "MissingAuth",
			Reason:               MissingAuthentication,
			ExpectedCode:         401,
			ExpectAuthTypeHeader: true,
		},
		{
			Description:          "ChecksNotFound",
			Reason:               ChecksNotFound,
			ExpectedCode:         403,
			ExpectAuthTypeHeader: false,
		},
		{
			Description:          "ChecksFailed",
			Reason:               ChecksFailed,
			ExpectedCode:         403,
			ExpectAuthTypeHeader: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Description, func(t *testing.T) {
			assert := assert.New(t)

			recorder := httptest.NewRecorder()
			DefaultOnErrorHTTPResponse(recorder, tc.Reason)
			assert.Equal(tc.ExpectedCode, recorder.Code)

			authType := recorder.Header().Get(AuthTypeHeaderKey)
			if tc.ExpectAuthTypeHeader {
				assert.Equal(string(BearerAuthorization), authType)
			} else {
				assert.Empty(authType)
			}
		})
	}
}

func TestLegacyOnErrorHTTPResponse(t *testing.T) {
	tcs := []struct {
		Description  string
		Reason       ErrorResponseReason
		ExpectedCode int
	}{
		{
			Description:  "MissingHeader",
			Reason:       MissingHeader,
			ExpectedCode: 403,
		},
		{
			Description:  "InvalidHeader",
			Reason:       InvalidHeader,
			ExpectedCode: 400,
		},
		{
			Description:  "KeyNotSupported",
			Reason:       KeyNotSupported,
			ExpectedCode: 403,
		},
		{
			Description:  "ParseFailed",
			Reason:       ParseFailed,
			ExpectedCode: 403,
		},
		{
			Description:  "GetURLFailed",
			Reason:       GetURLFailed,
			ExpectedCode: 403,
		},
		{
			Description:  "MissingAuth",
			Reason:       MissingAuthentication,
			ExpectedCode: 403,
		},
		{
			Description:  "ChecksNotFound",
			Reason:       ChecksNotFound,
			ExpectedCode: 403,
		},
		{
			Description:  "ChecksFailed",
			Reason:       ChecksFailed,
			ExpectedCode: 403,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Description, func(t *testing.T) {
			assert := assert.New(t)
			recorder := httptest.NewRecorder()
			LegacyOnErrorHTTPResponse(recorder, tc.Reason)
			assert.Equal(tc.ExpectedCode, recorder.Code)
			assert.Empty(recorder.Header().Get(AuthTypeHeaderKey))
		})
	}
}
