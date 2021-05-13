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

// ErrorResponseReason is an enum that specifies the reason parsing/validating
// a token failed.  Its primary use is for metrics and logging.
type ErrorResponseReason int

const (
	Unknown ErrorResponseReason = iota
	MissingHeader
	InvalidHeader
	KeyNotSupported
	ParseFailed
	GetURLFailed
	MissingAuthentication
	ChecksNotFound
	ChecksFailed
)

const (
	UnknownReason = "unknown"
)

var responseReasonMarshal = map[ErrorResponseReason]string{
	MissingHeader:         "missing_header",
	InvalidHeader:         "invalid_header",
	KeyNotSupported:       "key_not_supported",
	ParseFailed:           "parse_failed",
	GetURLFailed:          "get_url_failed",
	MissingAuthentication: "missing_authentication",
	ChecksNotFound:        "checks_not_found",
	ChecksFailed:          "checks_failed",
}

func (e ErrorResponseReason) String() string {
	reason, ok := responseReasonMarshal[e]
	if !ok {
		return UnknownReason
	}
	return reason
}
