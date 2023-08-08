// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"fmt"
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
