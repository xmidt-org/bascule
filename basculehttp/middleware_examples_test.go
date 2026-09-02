// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/xmidt-org/bascule"
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
				p, _ := t.Principal()
				fmt.Println("principal:", p)
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

// ExampleMiddleware_authentication shows how to authenticate a token.
func ExampleMiddleware_authentication() {
	tp, _ := NewAuthorizationParser(
		WithBasic(),
	)

	m, _ := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(tp),
				bascule.WithValidators(
					AsValidator(
						// the signature of validator closures is very flexible
						// see bascule.AsValidator
						func(token bascule.Token) error {
							if basic, ok := token.(BasicToken); ok && basic.Password() == "correct_password" {
								return nil
							}

							return bascule.ErrBadCredentials
						},
					),
				),
			),
		),
	)

	h := m.ThenFunc(
		func(response http.ResponseWriter, request *http.Request) {
			t, _ := bascule.GetFrom(request)
			p, _ := t.Principal()
			fmt.Println("principal:", p)
		},
	)

	requestForJoe := httptest.NewRequest("GET", "/", nil)
	requestForJoe.SetBasicAuth("joe", "correct_password")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestForJoe)
	fmt.Println("we let joe in with the code:", response.Code)

	requestForCurly := httptest.NewRequest("GET", "/", nil)
	requestForCurly.SetBasicAuth("joe", "bad_password")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, requestForCurly)
	fmt.Println("this isn't joe:", response.Code)

	// Output:
	// principal: joe
	// we let joe in with the code: 200
	// this isn't joe: 401
}

// ExampleMiddleware_authorization shows how to set up custom
// authorization for tokens.
func ExampleMiddleware_authorization() {
	tp, _ := NewAuthorizationParser(
		WithBasic(),
	)

	m, _ := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(tp),
			),
		),
		UseAuthorizer(
			NewAuthorizer(
				bascule.WithApproverFuncs(
					// this can also be a type that implements the bascule.Approver interface,
					// when used with bascule.WithApprovers
					func(ctx context.Context, resource *http.Request, token bascule.Token) error {
						if err := ctx.Err(); err != nil {
							return err
						}

						if p, _ := token.Principal(); p != "joe" {
							// only joe can access this resource
							return bascule.ErrUnauthorized
						}

						return nil // approved
					},
				),
			),
		),
	)

	h := m.ThenFunc(
		func(response http.ResponseWriter, request *http.Request) {
			t, _ := bascule.GetFrom(request)
			p, _ := t.Principal()
			fmt.Println("principal:", p)
		},
	)

	requestForJoe := httptest.NewRequest("GET", "/", nil)
	requestForJoe.SetBasicAuth("joe", "password")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestForJoe)
	fmt.Println("we let joe in with the code:", response.Code)

	requestForCurly := httptest.NewRequest("GET", "/", nil)
	requestForCurly.SetBasicAuth("curly", "another_password")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, requestForCurly)
	fmt.Println("we didn't authorize curly:", response.Code)

	// Output:
	// principal: joe
	// we let joe in with the code: 200
	// we didn't authorize curly: 403
}
