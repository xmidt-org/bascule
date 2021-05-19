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
