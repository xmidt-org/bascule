// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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

// String provides a metric label safe string of the response reason.
func (e ErrorResponseReason) String() string {
	reason, ok := responseReasonMarshal[e]
	if !ok {
		return UnknownReason
	}
	return reason
}
