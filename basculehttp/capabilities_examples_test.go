// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp/basculecaps"
)

// capabilitiesToken is a Token that carries capabilities, as a JWT parsed by
// basculejwt would.  The examples authenticate with a stub parser that always
// returns it, so that they can focus on authorization.
type capabilitiesToken struct {
	principal    string
	capabilities []string
}

func (t capabilitiesToken) Principal() string      { return t.principal }
func (t capabilitiesToken) Capabilities() []string { return t.capabilities }

// serve runs one request through a handler and reports the status code.
func serve(h http.Handler, method, target, remoteAddr string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	if remoteAddr != "" {
		request.RemoteAddr = remoteAddr
	}

	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)

	return response
}

// ExampleMiddleware_capabilities combines an endpoint approver, which grants
// access, with a CIDR approver, which limits it.  Every approver must agree.
func ExampleMiddleware_capabilities() {
	token := capabilitiesToken{
		principal: "joe",
		capabilities: []string{
			"webpa-prefix-api:/device/.*/config:get",
			"webpa-prefix-cidr:10.0.0.0/8",
		},
	}

	endpoints, _ := basculecaps.NewApprover(
		basculecaps.WithPrefixLiterals("webpa-prefix-api:"),
	)

	networks, _ := NewCIDRApprover(
		WithCIDRPrefixLiterals("webpa-prefix-cidr:"),
	)

	middleware, err := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(bascule.StubTokenParser[*http.Request]{Token: token}),
			),
		),
		UseAuthorizer(
			NewAuthorizer(
				bascule.WithApprovers(endpoints, networks),
			),
		),
	)
	if err != nil {
		panic(err)
	}

	handler := middleware.ThenFunc(func(http.ResponseWriter, *http.Request) {})

	fmt.Println("allowed endpoint, allowed network:", serve(handler, http.MethodGet, "/device/DEADBEEF/config", "10.1.2.3:1234").Code)
	fmt.Println("allowed endpoint, other network:  ", serve(handler, http.MethodGet, "/device/DEADBEEF/config", "203.0.113.9:1234").Code)
	fmt.Println("other endpoint, allowed network:  ", serve(handler, http.MethodDelete, "/device/DEADBEEF/config", "10.1.2.3:1234").Code)

	// Output:
	// allowed endpoint, allowed network: 200
	// allowed endpoint, other network:   403
	// other endpoint, allowed network:   403
}
