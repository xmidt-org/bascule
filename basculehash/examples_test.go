// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"golang.org/x/crypto/bcrypt"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehash"
	"github.com/xmidt-org/bascule/basculehttp"
)

// ExampleBcrypt shows how to produce a digest and later check a password
// against it.  The digest, not the password, is what a service stores.
func ExampleBcrypt() {
	hasher := basculehash.Bcrypt{Cost: bcrypt.MinCost} // the default cost is stronger, and slower

	digest, err := hasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		panic(err)
	}

	fmt.Println("matches:", hasher.Matches([]byte("correct horse battery staple"), digest) == nil)
	fmt.Println("matches:", hasher.Matches([]byte("Tr0ub4dor&3"), digest) == nil)

	// Output:
	// matches: true
	// matches: false
}

// ExampleNewValidator protects an HTTP handler with Basic authentication,
// checking each password against a bcrypt digest held in a Store.
func ExampleNewValidator() {
	// Digests are normally produced out of band, for example with
	// `go run github.com/xmidt-org/bascule/cmd/hash bcrypt 'the password'`,
	// and loaded from configuration.  Store implements encoding/json for that.
	digest, _ := basculehash.Bcrypt{Cost: bcrypt.MinCost}.Hash([]byte("secret"))

	var users basculehash.Store
	users.Set(context.Background(), "joe", digest)

	parser, _ := basculehttp.NewAuthorizationParser(
		basculehttp.WithBasic(),
	)

	middleware, err := basculehttp.NewMiddleware(
		basculehttp.UseAuthenticator(
			basculehttp.NewAuthenticator(
				bascule.WithTokenParsers(parser),
				bascule.WithValidators(
					// A nil Comparer means the default, which understands bcrypt.
					basculehash.NewValidator[*http.Request](nil, &users),
				),
			),
		),
	)
	if err != nil {
		panic(err)
	}

	handler := middleware.ThenFunc(func(response http.ResponseWriter, request *http.Request) {
		token, _ := bascule.GetFrom(request)
		fmt.Println("principal:", token.Principal())
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetBasicAuth("joe", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println("correct password:", response.Code)

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetBasicAuth("joe", "guess")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println("wrong password:", response.Code)

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetBasicAuth("nobody", "secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println("unknown principal:", response.Code)

	// Output:
	// principal: joe
	// correct password: 200
	// wrong password: 401
	// unknown principal: 401
}
