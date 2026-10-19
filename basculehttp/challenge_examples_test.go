// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"fmt"
	"net/http"

	"github.com/xmidt-org/bascule"
)

// ExampleWithChallenges tells clients how to authenticate.  Each configured
// challenge is written as a WWW-Authenticate header on a 401 response.
func ExampleWithChallenges() {
	parser, _ := NewAuthorizationParser(WithBasic())

	middleware, err := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(bascule.WithTokenParsers(parser)),
		),
		WithChallenges(
			NewBasicChallenge("example.com", true),
		),
	)
	if err != nil {
		panic(err)
	}

	handler := middleware.ThenFunc(func(http.ResponseWriter, *http.Request) {})

	response := serve(handler, http.MethodGet, "/", "")
	fmt.Println("status:", response.Code)
	fmt.Println("WWW-Authenticate:", response.Header().Get("WWW-Authenticate"))

	// Output:
	// status: 401
	// WWW-Authenticate: Basic realm="example.com", charset="UTF-8"
}
