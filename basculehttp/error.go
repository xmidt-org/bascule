// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"encoding"
	"encoding/json"
	"net/http"
)

// ErrorStatusCoder is a strategy for determining the HTTP response code for an error.
//
// The defaultCode is used when this strategy cannot determine the code from the error.
// This default can be a sentinel for decorators, e.g. zero (0), or can be an actual
// status code.
type ErrorStatusCoder func(request *http.Request, defaultCode int, err error) int

// DefaultErrorStatusCoder is the strategy used when no ErrorStatusCoder is supplied.
// This function examines err to see if it or any wrapped error provides a StatusCode()
// method.  If found, Status() is used.  Otherwise, this function returns the default code.
//
// This function can also be decorated.  Passing a sentinel value for defaultCode allows
// a decorator to take further action.
func DefaultErrorStatusCoder(_ *http.Request, defaultCode int, err error) int {
	type statusCoder interface {
		StatusCode() int
	}

	if sc, ok := err.(statusCoder); ok {
		return sc.StatusCode()
	}

	return defaultCode
}

// ErrorMarshaler is a strategy for marshaling an error's contents, particularly to
// be used in an HTTP response body.
type ErrorMarshaler func(request *http.Request, err error) (contentType string, content []byte, marshalErr error)

// DefaultErrorMarshaler examines the error for several standard marshalers.  The supported marshalers
// together with the returned content types are as follows:
//
//   - json.Marshaler                 "application/json"
//   - encoding.TextMarshaler         "text/plain; charset=utf-8"
//   - encoding.BinaryMarshaler       "application/octet-stream"
//
// If the error or any of its wrapped errors does not implement a supported marshaler interface,
// the error's Error() text is used with a content type of "text/plain; charset=utf-8".
func DefaultErrorMarshaler(_ *http.Request, err error) (contentType string, content []byte, marshalErr error) {
	switch m := err.(type) {
	case json.Marshaler:
		contentType = "application/json"
		content, marshalErr = m.MarshalJSON()

	case encoding.TextMarshaler:
		contentType = "text/plain; charset=utf-8"
		content, marshalErr = m.MarshalText()

	case encoding.BinaryMarshaler:
		contentType = "application/octet-stream"
		content, marshalErr = m.MarshalBinary()

	default:
		contentType = "text/plain; charset=utf-8"
		content = []byte(err.Error())
	}

	return
}
