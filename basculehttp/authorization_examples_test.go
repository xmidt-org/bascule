// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/xmidt-org/bascule"
)

// ExampleWithScheme registers a parser for a custom Authorization scheme.  The
// parser receives the part of the header after the scheme.  basculejwt's
// parser is registered for the Bearer scheme the same way.
func ExampleWithScheme() {
	// An API key scheme: "Authorization: ApiKey <key>".
	apiKeys := map[string]string{"k-123": "joe"}

	apiKeyParser := bascule.AsTokenParser[string](
		func(key string) (bascule.Token, error) {
			principal, ok := apiKeys[strings.TrimSpace(key)]
			if !ok {
				return nil, bascule.ErrBadCredentials
			}

			return bascule.StubToken(principal), nil
		},
	)

	parser, _ := NewAuthorizationParser(
		WithBasic(),
		WithScheme("ApiKey", apiKeyParser),
	)

	middleware, _ := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(bascule.WithTokenParsers(parser)),
		),
	)

	handler := middleware.ThenFunc(func(_ http.ResponseWriter, request *http.Request) {
		token, _ := bascule.GetFrom(request)
		fmt.Println("principal:", token.Principal())
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "ApiKey k-123")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println("known key:", response.Code)

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "ApiKey k-999")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println("unknown key:", response.Code)

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Digest abc")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println("unregistered scheme:", response.Code)

	// Output:
	// principal: joe
	// known key: 200
	// unknown key: 401
	// unregistered scheme: 401
}

// ExampleUseStatusCode overrides the status code a particular error produces.
// Here an approver turns a quota failure into 429 rather than the usual 403.
func ExampleUseStatusCode() {
	errQuotaExceeded := errors.New("quota exceeded")

	middleware, _ := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(bascule.StubTokenParser[*http.Request]{Token: bascule.StubToken("joe")}),
			),
		),
		UseAuthorizer(
			NewAuthorizer(
				bascule.WithApproverFuncs(
					func(_ context.Context, _ *http.Request, _ bascule.Token) error {
						return UseStatusCode(http.StatusTooManyRequests, errQuotaExceeded)
					},
				),
			),
		),
	)

	handler := middleware.ThenFunc(func(http.ResponseWriter, *http.Request) {})

	response := serve(handler, http.MethodGet, "/", "")
	fmt.Println("status:", response.Code)
	fmt.Println("body:", strings.TrimSpace(response.Body.String()))

	// Output:
	// status: 429
	// body: quota exceeded
}
