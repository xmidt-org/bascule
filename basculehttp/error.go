// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
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
	// check if it's a status coder first, so that we can
	// override status codes for built-in errors.
	case errors.As(err, &sc):
		return sc.StatusCode()

	case errors.Is(err, bascule.ErrMissingCredentials):
		return http.StatusUnauthorized

	case errors.Is(err, bascule.ErrInvalidCredentials):
		return http.StatusBadRequest
	}

	return 0
}

// ErrorMarshaler is a strategy for marshaling an error's contents, particularly to
// be used in an HTTP response body.
type ErrorMarshaler func(request *http.Request, err error) (contentType string, content []byte, marshalErr error)

// DefaultErrorMarshaler returns a plaintext representation of the error.
func DefaultErrorMarshaler(_ *http.Request, err error) (contentType string, content []byte, marshalErr error) {
	contentType = "text/plain; charset=utf-8"
	content = []byte(err.Error())
	return
}

type statusCodeError struct {
	error
	statusCode int
}

func (err *statusCodeError) Unwrap() error {
	return err.error
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
