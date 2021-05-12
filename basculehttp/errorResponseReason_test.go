package basculehttp

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorResponseReasonStr(t *testing.T) {
	tests := []struct {
		reason         ErrorResponseReason
		expectedString string
	}{
		{
			reason:         MissingHeader,
			expectedString: "missing_header",
		},
		{
			reason:         InvalidHeader,
			expectedString: "invalid_header",
		},
		{
			reason:         KeyNotSupported,
			expectedString: "key_not_supported",
		},
		{
			reason:         ParseFailed,
			expectedString: "parse_failed",
		},
		{
			reason:         GetURLFailed,
			expectedString: "get_url_failed",
		},
		{
			reason:         MissingAuthentication,
			expectedString: "missing_authentication",
		},
		{
			reason:         ChecksNotFound,
			expectedString: "checks_not_found",
		},
		{
			reason:         ChecksFailed,
			expectedString: "checks_failed",
		},
		{
			reason:         -1,
			expectedString: UnknownReason,
		},
		{
			reason:         0,
			expectedString: UnknownReason,
		},
		{
			reason:         1000,
			expectedString: UnknownReason,
		},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%v %v", tc.reason, tc.expectedString),
			func(t *testing.T) {
				r := tc.reason.String()
				assert.Equal(t, tc.expectedString, r)
			})
	}
}

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
