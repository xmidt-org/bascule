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

import "net/http"

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

// AuthTypeHeaderKey is the header key that's used when requests are denied
// with a 401 status code. It specifies the suggested token type that should
// be used for a successful request.
const AuthTypeHeaderKey = "WWW-Authenticate"

// OnErrorResponse is a function that takes the error response reason and the
// error and can do something with it.  This is useful for adding additional
// metrics or logs.
type OnErrorResponse func(ErrorResponseReason, error)

// default function does nothing
func DefaultOnErrorResponse(_ ErrorResponseReason, _ error) {
}

// OnErrorHTTPResponse allows users to decide what the response should be
// for a given reason.
type OnErrorHTTPResponse func(http.ResponseWriter, ErrorResponseReason)

// DefaultOnErrorHTTPResponse will write a 401 status code along the
// 'WWW-Authenticate: Bearer' header for all error cases related to building
// the security token. For error checks that happen once a valid token has been
// created will result in a 403.
func DefaultOnErrorHTTPResponse(w http.ResponseWriter, reason ErrorResponseReason) {
	switch reason {
	case ChecksNotFound, ChecksFailed:
		w.WriteHeader(http.StatusForbidden)
	default:
		w.Header().Set(AuthTypeHeaderKey, string(BearerAuthorization))
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// LegacyOnErrorHTTPResponse will write a 403 status code back for any error
// reason except for InvalidHeader for which a 400 is written.
func LegacyOnErrorHTTPResponse(w http.ResponseWriter, reason ErrorResponseReason) {
	switch reason {
	case InvalidHeader:
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusForbidden)
	}
}
