// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"encoding"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/xmidt-org/bascule/v1"
)

// ErrorStatusCoder is a strategy for determining the HTTP response code for an error.
//
// If this closure returns a value less than 100, which is the smallest valid HTTP
// response code, the caller should supply a useful default.
type ErrorStatusCoder func(request *http.Request, err error) int

// DefaultErrorStatusCoder is the strategy used when no ErrorStatusCoder is supplied.
//
// If err has bascule.ErrMissingCredentials in its chain, this function returns
// http.StatusUnauthorized.
//
// If err has bascule.ErrInvalidCredentials in its chain, this function returns
// http.StatusBadRequest.
//
// Failing the previous two checks, if the error provides a StatusCode() method,
// the return value from that method is used.
//
// Otherwise, this method returns 0 to indicate that it doesn't know how to
// produce a status code from the error.
func DefaultErrorStatusCoder(_ *http.Request, err error) int {
	type statusCoder interface {
		StatusCode() int
	}

	var sc statusCoder

	switch {
	case errors.Is(err, bascule.ErrMissingCredentials):
		return http.StatusUnauthorized

	case errors.Is(err, bascule.ErrInvalidCredentials):
		return http.StatusBadRequest

	case errors.As(err, &sc):
		return sc.StatusCode()
	}

	return 0
}

// ErrorMarshaler is a strategy for marshaling an error's contents, particularly to
// be used in an HTTP response body.
type ErrorMarshaler func(request *http.Request, err error) (contentType string, content []byte, marshalErr error)

// DefaultErrorMarshaler examines the error for several standard marshalers.  The supported marshalers
// together with the returned content types are as follows, in order:
//
//   - json.Marshaler                 "application/json"
//   - encoding.TextMarshaler         "text/plain; charset=utf-8"
//   - encoding.BinaryMarshaler       "application/octet-stream"
//
// If the error or any of its wrapped errors does not implement a supported marshaler interface,
// the error's Error() text is used with a content type of "text/plain; charset=utf-8".
func DefaultErrorMarshaler(_ *http.Request, err error) (contentType string, content []byte, marshalErr error) {
	// walk the wrapped errors manually, since that's way more efficient
	// that walking the error tree once for each desired type
	for wrapped := err; wrapped != nil && len(content) == 0 && marshalErr == nil; wrapped = errors.Unwrap(wrapped) {
		switch m := wrapped.(type) { //nolint: errorlint
		case json.Marshaler:
			contentType = "application/json"
			content, marshalErr = m.MarshalJSON()

		case encoding.TextMarshaler:
			contentType = "text/plain; charset=utf-8"
			content, marshalErr = m.MarshalText()

		case encoding.BinaryMarshaler:
			contentType = "application/octet-stream"
			content, marshalErr = m.MarshalBinary()
		}
	}

	if len(content) == 0 && marshalErr == nil {
		// fallback
		contentType = "text/plain; charset=utf-8"
		content = []byte(err.Error())
	}

	return
}

type statusCodeError struct {
	error
	statusCode int
}

func (err *statusCodeError) StatusCode() int {
	return err.statusCode
}

// UseStatusCode associates an HTTP status code with the given error.
// This function will override any existing status code associated with err.
func UseStatusCode(statusCode int, err error) error {
	return &statusCodeError{
		error:      err,
		statusCode: statusCode,
	}
}
