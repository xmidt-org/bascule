// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/xmidt-org/bascule"
)

// newCIDRHandler protects a no-op handler with a CIDR approver built from opts,
// authenticating every request as the given token.
func newCIDRHandler(token bascule.Token, opts ...CIDRApproverOption) http.Handler {
	networks, err := NewCIDRApprover(opts...)
	if err != nil {
		panic(err)
	}

	middleware, err := NewMiddleware(
		UseAuthenticator(
			NewAuthenticator(
				bascule.WithTokenParsers(bascule.StubTokenParser[*http.Request]{Token: token}),
			),
		),
		UseAuthorizer(
			NewAuthorizer(bascule.WithApprovers(networks)),
		),
		// Each capability warning becomes one instance of this header.
		WithWarningHeader("X-Capability-Warning"),
	)
	if err != nil {
		panic(err)
	}

	return middleware.ThenFunc(func(http.ResponseWriter, *http.Request) {})
}

// ExampleNewCIDRApprover restricts a token to requests from the networks it
// names.  CIDR capabilities only limit access, so a token carrying none is
// unrestricted by default.
func ExampleNewCIDRApprover() {
	restricted := capabilitiesToken{
		principal:    "joe",
		capabilities: []string{"webpa-prefix-cidr:10.0.0.0/8", "webpa-prefix-cidr:2001:db8::/32"},
	}

	unrestricted := capabilitiesToken{
		principal: "anyone",
	}

	handler := newCIDRHandler(restricted, WithCIDRPrefixLiterals("webpa-prefix-cidr:"))
	fmt.Println("restricted, inside:  ", serve(handler, http.MethodGet, "/", "10.1.2.3:1234").Code)
	fmt.Println("restricted, inside v6:", serve(handler, http.MethodGet, "/", "[2001:db8::1]:1234").Code)
	fmt.Println("restricted, outside: ", serve(handler, http.MethodGet, "/", "203.0.113.9:1234").Code)

	handler = newCIDRHandler(unrestricted, WithCIDRPrefixLiterals("webpa-prefix-cidr:"))
	fmt.Println("unrestricted:        ", serve(handler, http.MethodGet, "/", "203.0.113.9:1234").Code)

	// WithCIDRRequired reverses the default: a token must carry a network.
	handler = newCIDRHandler(unrestricted, WithCIDRPrefixLiterals("webpa-prefix-cidr:"), WithCIDRRequired())
	fmt.Println("unrestricted, required:", serve(handler, http.MethodGet, "/", "203.0.113.9:1234").Code)

	// Output:
	// restricted, inside:   200
	// restricted, inside v6: 200
	// restricted, outside:  403
	// unrestricted:         200
	// unrestricted, required: 403
}

// ExampleNewCIDRApprover_permissive trials a restriction before enforcing it.
// Requests that would be rejected are let through, and the reason is reported
// to the caller as a warning.
func ExampleNewCIDRApprover_permissive() {
	restricted := capabilitiesToken{
		principal:    "joe",
		capabilities: []string{"webpa-prefix-cidr:10.0.0.0/8"},
	}

	malformed := capabilitiesToken{
		principal:    "joe",
		capabilities: []string{"webpa-prefix-cidr:10.0.0.0"}, // a bare address is not a network
	}

	handler := newCIDRHandler(restricted,
		WithCIDRPrefixLiterals("webpa-prefix-cidr:"),
		WithCIDRPermissiveRequired(), // later: WithCIDRRequired()
	)

	response := serve(handler, http.MethodGet, "/", "203.0.113.9:1234")
	fmt.Println("outside:", response.Code)
	fmt.Println("warning:", response.Header().Get("X-Capability-Warning"))

	handler = newCIDRHandler(malformed,
		WithCIDRPrefixLiterals("webpa-prefix-cidr:"),
		WithCIDRPermissiveRequired(),
	)

	// A malformed capability counts as present but matches nothing, so the
	// token is not unrestricted.  Both problems are reported.
	response = serve(handler, http.MethodGet, "/", "10.1.2.3:1234")
	fmt.Println("malformed:", response.Code)
	for _, w := range response.Header().Values("X-Capability-Warning") {
		fmt.Println("warning:", w)
	}

	// Output:
	// outside: 200
	// warning: would-reject; kind=cidr; reason=origin-not-allowed; origin=203.0.113.9
	// malformed: 200
	// warning: malformed; kind=cidr; cap="webpa-prefix-cidr:10.0.0.0"
	// warning: would-reject; kind=cidr; reason=origin-not-allowed; origin=10.1.2.3
}

// ExampleWithCIDRResolver gives the server the final say over the networks a
// token counts as carrying.  Here the networks come from configuration, keyed
// by the token's principal, which for a JWT is its sub claim, for an issuer
// that does not put networks in its tokens.  The same hook can override,
// cap or require networks, or block a principal outright.
func ExampleWithCIDRResolver() {
	// Typically unmarshaled from configuration, then parsed once.
	configured := map[string][]netip.Prefix{
		"joe": {netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")},
	}

	resolver := func(_ context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error) {
		if principal == "mallory" {
			return nil, errors.New("mallory is blocked") // logged by the service, not shown to the caller
		}

		// A configured network counts exactly as if the token carried it,
		// alongside any it does carry.
		return append(provided, configured[principal]...), nil
	}

	joe := capabilitiesToken{principal: "joe"}
	opts := []CIDRApproverOption{
		WithCIDRPrefixLiterals("webpa-prefix-cidr:"),
		WithCIDRResolver(resolver),
	}

	handler := newCIDRHandler(joe, opts...)
	fmt.Println("joe, inside:    ", serve(handler, http.MethodGet, "/", "10.1.2.3:1234").Code)
	fmt.Println("joe, outside:   ", serve(handler, http.MethodGet, "/", "203.0.113.9:1234").Code)

	// A principal the resolver returns no networks for is unrestricted by
	// default ...
	anyone := capabilitiesToken{principal: "anyone"}
	handler = newCIDRHandler(anyone, opts...)
	fmt.Println("anyone:         ", serve(handler, http.MethodGet, "/", "203.0.113.9:1234").Code)

	// ... unless a network is required.
	handler = newCIDRHandler(anyone, WithCIDRPrefixLiterals("webpa-prefix-cidr:"), WithCIDRResolver(resolver), WithCIDRRequired())
	fmt.Println("anyone, required:", serve(handler, http.MethodGet, "/", "203.0.113.9:1234").Code)

	mallory := capabilitiesToken{principal: "mallory"}
	handler = newCIDRHandler(mallory, opts...)
	fmt.Println("mallory:        ", serve(handler, http.MethodGet, "/", "10.1.2.3:1234").Code)

	// Output:
	// joe, inside:     200
	// joe, outside:    403
	// anyone:          200
	// anyone, required: 403
	// mallory:         403
}
