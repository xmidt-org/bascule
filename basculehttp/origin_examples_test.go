// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
)

// ExampleNewOriginResolver finds the address a request came from when it
// arrived through a load balancer.  Only hops the deployment trusts are
// skipped; a Forwarded header from anywhere else is ignored.
func ExampleNewOriginResolver() {
	resolver, err := NewOriginResolver(
		WithTrustedProxies(netip.MustParsePrefix("10.1.0.0/16")),
	)
	if err != nil {
		panic(err)
	}

	// Through the load balancer: the origin is what the balancer reports.
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.0.7:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	origin, ok := resolver.Origin(request)
	fmt.Println("via trusted proxy:", origin, ok)

	// Directly from a client that forged the same header: the header is ignored.
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "198.51.100.4:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	origin, ok = resolver.Origin(request)
	fmt.Println("direct, forged header:", origin, ok)

	// A CIDR approver uses the resolver through WithOriginResolver.
	_, err = NewCIDRApprover(
		WithCIDRPrefixLiterals("webpa-prefix-cidr:"),
		WithOriginResolver(resolver),
	)
	fmt.Println("approver configured:", err == nil)

	// Output:
	// via trusted proxy: 203.0.113.9 true
	// direct, forged header: 198.51.100.4 true
	// approver configured: true
}
