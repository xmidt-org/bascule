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

// package basculehttp contains some basic http middleware (in the form of
// Alice-style decorators) that can be used to extract and parse a Token from
// an http header, validate the Token, and  allow for the consumer to add
// additional logs or metrics upon an error or a valid Token.
package basculehttp

import "net/http"

// statusCode follows the go-kit convention.  Errors and other objects that implement
// this interface are allowed to supply an HTTP response status code.
type statusCoder interface {
	StatusCode() int
}

// headerer allows errors and other types to supply headers, mainly for writing
// HTTP responses.
type headerer interface {
	Headers() http.Header
}

// ErrorHeaderer implements headerer, allowing an error to supply http headers
// in an error response.
type ErrorHeaderer struct {
	err     error
	headers http.Header
}

func (e ErrorHeaderer) Error() string {
	return e.err.Error()
}

func (e ErrorHeaderer) Headers() http.Header {
	return e.headers
}

func NewErrorHeaderer(err error, headers map[string][]string) error {
	return ErrorHeaderer{err: err, headers: headers}
}

// WriteResponse performs some basic reflection on v to allow it to modify responses written
// to an HTTP response.  Useful mainly for errors.
func WriteResponse(response http.ResponseWriter, defaultStatusCode int, v interface{}) {
	if h, ok := v.(headerer); ok {
		for name, values := range h.Headers() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
	}

	status := defaultStatusCode
	if s, ok := v.(statusCoder); ok {
		status = s.StatusCode()
	}

	response.WriteHeader(status)
}
