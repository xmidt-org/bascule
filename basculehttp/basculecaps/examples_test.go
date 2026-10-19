// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp/basculecaps"
)

// exampleToken is a Token that carries capabilities.  A JWT parsed by
// basculejwt carries them the same way, from its "capabilities" claim.
type exampleToken struct {
	principal    string
	capabilities []string
}

func (t exampleToken) Principal() string      { return t.principal }
func (t exampleToken) Capabilities() []string { return t.capabilities }

// ExampleNewApprover authorizes requests from the endpoint capabilities a
// token carries.  Each capability is <prefix><url pattern>:<method>.
func ExampleNewApprover() {
	approver, err := basculecaps.NewApprover(
		// Only capabilities beginning with this exact string are considered.
		basculecaps.WithPrefixLiterals("webpa-prefix-api:"),
	)
	if err != nil {
		panic(err)
	}

	token := exampleToken{
		principal: "joe",
		capabilities: []string{
			"webpa-prefix-api:/device/.*/config:get",
			"webpa-prefix-api:/device/.*/stat:all",
			"other-prefix-service:/admin:all", // a different prefix, so ignored here
		},
	}

	for _, target := range []string{
		"GET /device/DEADBEEF/config",
		"PUT /device/DEADBEEF/config",
		"DELETE /device/DEADBEEF/stat",
		"GET /admin",
	} {
		method, path, _ := strings.Cut(target, " ")
		request := httptest.NewRequest(method, path, nil)

		err := approver.Approve(context.Background(), request, token)
		fmt.Printf("%-28s approved: %t\n", target, err == nil)
	}

	// Output:
	// GET /device/DEADBEEF/config  approved: true
	// PUT /device/DEADBEEF/config  approved: false
	// DELETE /device/DEADBEEF/stat approved: true
	// GET /admin                   approved: false
}

// ExampleApprover_Approve_errors shows the two questions a denial answers:
// did the token have no capabilities at all, or none that matched?
func ExampleApprover_Approve_errors() {
	approver, _ := basculecaps.NewApprover(
		basculecaps.WithPrefixLiterals("webpa-prefix-api:"),
	)

	request := httptest.NewRequest(http.MethodGet, "/device/DEADBEEF/config", nil)

	err := approver.Approve(context.Background(), request, exampleToken{principal: "joe"})
	fmt.Println("unauthorized:", errors.Is(err, bascule.ErrUnauthorized))
	fmt.Println("no capabilities:", errors.Is(err, basculecaps.ErrNoCapabilities))

	err = approver.Approve(context.Background(), request, exampleToken{
		principal:    "joe",
		capabilities: []string{"webpa-prefix-api:/other:get"},
	})
	fmt.Println("unauthorized:", errors.Is(err, bascule.ErrUnauthorized))
	fmt.Println("no capabilities:", errors.Is(err, basculecaps.ErrNoCapabilities))
	fmt.Println("no matching capability:", errors.Is(err, basculecaps.ErrNoMatchingCapability))

	// Output:
	// unauthorized: true
	// no capabilities: true
	// unauthorized: true
	// no capabilities: false
	// no matching capability: true
}

// ExampleWithURLNormalizeFunc strips an API version from the request path, so
// that capabilities need not mention it.
func ExampleWithURLNormalizeFunc() {
	approver, _ := basculecaps.NewApprover(
		basculecaps.WithPrefixLiterals("webpa-prefix-api:"),
		basculecaps.WithURLNormalizeFunc(func(u url.URL) url.URL {
			u.Path = strings.TrimPrefix(u.Path, "/api/v2")
			return u
		}),
	)

	token := exampleToken{
		principal:    "joe",
		capabilities: []string{"webpa-prefix-api:/device/.*/config:get"},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v2/device/DEADBEEF/config", nil)
	err := approver.Approve(context.Background(), request, token)
	fmt.Println("approved:", err == nil)

	// Output:
	// approved: true
}
