// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/xmidt-org/bascule/v1"
)

// ExampleMiddleware_basicauth illustrates how to use a basculehttp Middleware with
// just basic auth.
func ExampleMiddleware_basicauth() {
	tp, _ := NewAuthorizationParser(
		WithBasic(),
	)

	m, _ := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(tp),
			),
		),
	)

	// decorate a handler that needs authorization
	h := m.ThenFunc(
		func(response http.ResponseWriter, request *http.Request) {
			if t, ok := bascule.GetFrom(request); ok {
				fmt.Println("principal:", t.Principal())
			} else {
				fmt.Println("no token found")
			}
		},
	)

	// what happens when no authorization is set?
	noAuth := httptest.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, noAuth)
	fmt.Println("no authorization response code:", response.Code)

	// what happens when a valid Basic token is set?
	withBasic := httptest.NewRequest("GET", "/", nil)
	withBasic.SetBasicAuth("joe", "password")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, withBasic)
	fmt.Println("with basic auth response code:", response.Code)

	// Output:
	// no authorization response code: 401
	// principal: joe
	// with basic auth response code: 200
}
