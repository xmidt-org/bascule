# bascule

Authentication and authorization for Go services, with first-class HTTP support.

[![Build Status](https://github.com/xmidt-org/bascule/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/bascule/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/xmidt-org/bascule/branch/main/graph/badge.svg)](https://app.codecov.io/gh/xmidt-org/bascule/tree/main)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/bascule/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/bascule.svg)](https://github.com/xmidt-org/bascule/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/bascule)](https://pkg.go.dev/github.com/xmidt-org/bascule)

Bascule turns a request's credentials into a **Token**, checks that the Token
is acceptable, and then decides whether that Token may do what the request
asks. Each of those steps is a small interface you can replace, and the
library ships implementations for the common cases: Basic and Bearer
authorization headers, JWTs, bcrypt password stores, URL capabilities and
network (CIDR) restrictions.

## Table of Contents

- [How it fits together](#how-it-fits-together)
- [Packages](#packages)
- [Install](#install)
- [Quick start: Basic auth over HTTP](#quick-start-basic-auth-over-http)
- [JWTs](#jwts)
- [Authorizing with capabilities](#authorizing-with-capabilities)
- [Errors, status codes and challenges](#errors-status-codes-and-challenges)
- [Extending bascule](#extending-bascule)
- [Further reading](#further-reading)
- [Versioning](#versioning)
- [Code of Conduct](#code-of-conduct)
- [Contributing](#contributing)

## How it fits together

A request passes through two stages.

1. **Authentication** produces a Token. An `Authenticator` runs one or more
   `TokenParser`s to read credentials from the request, then one or more
   `Validator`s to accept or reject the result, for example by checking a
   password or a JWT's claims.
2. **Authorization** decides what the Token may do. An `Authorizer` runs one
   or more `Approver`s against the request and the Token. Every Approver must
   agree; the first to object wins.

For HTTP, `basculehttp.Middleware` wires both stages in front of a handler.
A failed authentication produces `401`, a failed authorization produces
`403`, and the handler sees the Token via `bascule.GetFrom(request)`.

The core types are generic over the source of credentials, `S`, and the
resource being protected, `R`. For HTTP both are `*http.Request`.

## Packages

| Package | What it provides |
|---|---|
| `bascule` | The core model: `Token`, `Authenticator`, `Authorizer`, `Validator`, `Approver`, event listeners, capability warnings. |
| `basculehttp` | HTTP middleware, `Authorization` header parsing (Basic, Bearer, custom schemes), `WWW-Authenticate` challenges, caller origin resolution behind trusted proxies, and a CIDR approver. |
| `basculehttp/basculecaps` | An approver that authorizes HTTP requests from URL-and-method capabilities carried by the Token. |
| `basculejwt` | A `TokenParser` for JWTs, built on [jwx](https://github.com/lestrrat-go/jwx), with typed errors for each way a JWT can be rejected. |
| `basculehash` | Password hashing (bcrypt), a credential store, and a `Validator` that checks a Token's password against it. |
| `cmd/hash` | A small CLI that produces digests for `basculehash`. |

## Install

```sh
go get github.com/xmidt-org/bascule
```

Go 1.27 or later is required.

## Quick start: Basic auth over HTTP

The example below protects a handler with HTTP Basic authentication. Passwords
are checked against bcrypt digests held in memory.

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehash"
	"github.com/xmidt-org/bascule/basculehttp"
)

func main() {
	// Digests are produced out of band, for example with:
	//   go run github.com/xmidt-org/bascule/cmd/hash bcrypt 'the password'
	var users basculehash.Store
	users.Set(context.Background(), "joe", basculehash.Digest("$2a$10$..."))

	// Read the Authorization header, accepting the Basic scheme.
	parser, err := basculehttp.NewAuthorizationParser(
		basculehttp.WithBasic(),
	)
	if err != nil {
		log.Fatal(err)
	}

	middleware, err := basculehttp.NewMiddleware(
		basculehttp.UseAuthenticator(
			basculehttp.NewAuthenticator(
				bascule.WithTokenParsers(parser),
				bascule.WithValidators(
					// Reject tokens whose password does not match the stored digest.
					basculehash.NewValidator[*http.Request](nil, &users),
				),
			),
		),
		// Tell clients how to authenticate when they have not.
		basculehttp.WithChallenges(
			basculehttp.NewBasicChallenge("example", true),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	handler := middleware.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := bascule.GetFrom(r)
		w.Write([]byte("hello, " + token.Principal()))
	})

	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

`UseAuthenticator` accepts the `(*Authenticator, error)` pair that
`NewAuthenticator` returns, so construction errors surface from
`NewMiddleware` instead of needing a separate check.

Runnable examples:
[`ExampleNewValidator`](basculehash/examples_test.go) is this program with
real digests and requests;
[`ExampleBcrypt`](basculehash/examples_test.go) hashes and checks a password;
[`ExampleMiddleware_authentication`](basculehttp/middleware_examples_test.go)
and
[`ExampleMiddleware_authorization`](basculehttp/middleware_examples_test.go)
add a custom validator and a custom approver.

## JWTs

`basculejwt.NewTokenParser` returns a `TokenParser` for the raw value of a
`Bearer` header. It takes the same options as
[`jwt.Parse`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwt#Parse), so
key sets, issuers, audiences and clock skew are configured there.

```go
jwtParser, err := basculejwt.NewTokenParser(
	jwt.WithKeySet(keys),              // a jwk.Set, or jwk.NewCache(...) for a remote JWKS
	jwt.WithIssuer("https://issuer.example.com"),
	jwt.WithAudience("my-service"),
)
if err != nil {
	log.Fatal(err)
}

parser, err := basculehttp.NewAuthorizationParser(
	basculehttp.WithScheme(basculehttp.SchemeBearer, jwtParser),
)
```

The resulting Token's `Principal()` is the JWT's `sub` claim. A
`capabilities` claim holding a list of strings is exposed through
`bascule.GetCapabilities`, which is what the approvers below consume.

Rejections carry typed errors, so a caller can distinguish an expired token
from an unverifiable one without importing jwx:

```go
switch {
case errors.Is(err, basculejwt.ErrExpired):
case errors.Is(err, basculejwt.ErrInvalidSignature):
case errors.Is(err, bascule.ErrBadCredentials): // any rejection at all
}
```

Runnable examples: [`ExampleNewTokenParser`](basculejwt/examples_test.go)
signs and parses a JWT with capabilities, and
[`ExampleNewTokenParser_rejected`](basculejwt/examples_test.go) tells an
expired token from a bad signature.

## Authorizing with capabilities

A **capability** is one flat string carried by a Token. A Token may carry
capabilities meant for many services, so every approver is configured with a
**prefix** that selects the ones it honors; capabilities matching no prefix
are ignored. A prefix is matched literally. If you need a pattern, there is a
separate regex option, and it is anchored at the start of the capability.

### Endpoint capabilities

`basculecaps.Approver` grants access to HTTP endpoints. After the prefix, a
capability is `<url pattern>:<method>`:

```
webpa-prefix-api:/device/.*/config:get
webpa-prefix-api:/device/.*/config:all
```

The URL pattern is a regular expression matched against the start of the
request path, with or without its leading `/`. The method is lowercase, and
`all` matches every method. A Token with no endpoint capability under the
prefix is denied, because endpoint capabilities *grant* access.

```go
endpoints, err := basculecaps.NewApprover(
	basculecaps.WithPrefixLiterals("webpa-prefix-api:"),
)
```

Runnable examples: [`ExampleNewApprover`](basculehttp/basculecaps/examples_test.go)
approves and denies a set of requests,
[`ExampleApprover_Approve_errors`](basculehttp/basculecaps/examples_test.go)
shows the two kinds of denial, and
[`ExampleWithURLNormalizeFunc`](basculehttp/basculecaps/examples_test.go)
strips an API version before matching.

### CIDR capabilities

`basculehttp.CIDRApprover` restricts where a request may come from. After the
prefix, a capability is a network in CIDR notation:

```
webpa-prefix-cidr:10.0.0.0/8
webpa-prefix-cidr:2001:db8::/32
```

CIDR capabilities only *limit* access, so by default a Token carrying none is
unrestricted. `WithCIDRRequired` reverses that. The permissive modes let the
request through and record what would have been rejected as a warning, which
is how to trial a new restriction without breaking clients.

A `CIDRResolver` has the final say over the networks a Token counts as
carrying. It is a function of the request context, the Token's principal,
which for a JWT is the `sub` claim, and the networks the Token carries, and
whatever it returns is used instead. That one hook covers networks configured
per principal on the server, for an issuer that does not put them in Tokens,
as well as overriding, capping or requiring networks, or blocking a
principal by returning an error.

The request's origin is its `RemoteAddr` unless an `OriginResolver` with
trusted proxies is supplied, in which case it is the nearest hop that is not a
trusted proxy, read from `Forwarded` or `X-Forwarded-For`.

```go
origin, err := basculehttp.NewOriginResolver(
	basculehttp.WithTrustedProxies(netip.MustParsePrefix("10.1.0.0/16")),
)

// networks configured per principal, e.g. from the service's configuration
configured := map[string][]netip.Prefix{
	"device-service": {netip.MustParsePrefix("10.1.0.0/16")},
}

networks, err := basculehttp.NewCIDRApprover(
	basculehttp.WithCIDRPrefixLiterals("webpa-prefix-cidr:"),
	basculehttp.WithCIDRResolver(func(_ context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error) {
		return append(provided, configured[principal]...), nil
	}),
	basculehttp.WithOriginResolver(origin),
	basculehttp.WithCIDRPermissiveRequired(), // warn for now; switch to WithCIDRRequired later
)
```

Runnable examples: [`ExampleNewCIDRApprover`](basculehttp/cidr_examples_test.go)
covers the default and required modes,
[`ExampleWithCIDRResolver`](basculehttp/cidr_examples_test.go) adds networks
configured per principal and blocks one,
[`ExampleNewCIDRApprover_permissive`](basculehttp/cidr_examples_test.go)
shows the warnings a trial run produces, and
[`ExampleNewOriginResolver`](basculehttp/origin_examples_test.go) shows a
trusted proxy being honored and a forged header being ignored.

### Putting approvers together

```go
middleware, err := basculehttp.NewMiddleware(
	basculehttp.UseAuthenticator(
		basculehttp.NewAuthenticator(bascule.WithTokenParsers(parser)),
	),
	basculehttp.UseAuthorizer(
		basculehttp.NewAuthorizer(
			bascule.WithApprovers(endpoints, networks),
		),
	),
	// Surface capability warnings to the caller in a response header.
	basculehttp.WithWarningHeader("X-Capability-Warning"),
)
```

Approvers run in order and all must pass. Any `bascule.Approver[*http.Request]`
or plain function of the same shape can join the list.

Runnable example:
[`ExampleMiddleware_capabilities`](basculehttp/capabilities_examples_test.go)
runs both approvers together.

## Errors, status codes and challenges

The middleware maps errors to responses:

| Outcome | Status | Notes |
|---|---|---|
| No credentials | `401` | `WWW-Authenticate` is set from `WithChallenges`. |
| Credentials rejected by a validator | `401` | For example a wrong password or an expired JWT. |
| Credentials present but unreadable | `400` | For example a malformed header or JWT. |
| Authenticated but rejected by an approver | `403` | |
| Any other authentication error | `400` | |
| Any other authorization error | `403` | |

Each returned error is joined with one of the sentinel errors in `bascule`,
such as `ErrMissingCredentials`, `ErrBadCredentials` or `ErrUnauthorized`,
and usually with a more specific error from the package that produced it.
Use `errors.Is` to ask either question. An error can carry an explicit
status with `basculehttp.UseStatusCode`, and the mapping itself is replaceable
through `WithErrorStatusCoder` and `WithErrorMarshaler`.

Runnable examples: [`ExampleWithChallenges`](basculehttp/challenge_examples_test.go)
shows the `WWW-Authenticate` header on a `401`, and
[`ExampleUseStatusCode`](basculehttp/authorization_examples_test.go) turns an
approver's error into a `429`.

## Extending bascule

Every stage is an interface, and each has a function adapter so a closure is
enough.

- **A new credential format.** Implement `bascule.TokenParser[S]`, or wrap a
  function with `bascule.AsTokenParser`. Register it for an HTTP scheme with
  `basculehttp.WithScheme`. See
  [`ExampleWithScheme`](basculehttp/authorization_examples_test.go), which
  adds an API key scheme.
- **A new acceptance rule.** Implement `bascule.Validator[S]`, or wrap a
  function with `bascule.AsValidator`. A validator may also return a
  replacement Token, which is how to attach extra information: see
  [`ExampleJoinTokens_augment`](authenticator_examples_test.go).
- **A new authorization check.** Implement `bascule.Approver[R]`, or pass a
  function to `bascule.WithApproverFuncs`. An approver that only limits access
  should follow the pattern set by the CIDR approver: select its capabilities
  by prefix, treat a malformed one as present but matching nothing, and report
  problems with `bascule.AddWarning`.
- **Audit and metrics.** `WithAuthenticateListeners` and
  `WithAuthorizeListeners` receive an event for every attempt, successful or
  not, with the source, the Token and the error. See
  [`ExampleWithAuthenticateListeners`](authenticator_examples_test.go).

Every example linked from this document is an `Example` function that
`go test` runs and checks against its `// Output:` block, so they cannot
drift from the code.

## Further reading

- [`CONTEXT.md`](CONTEXT.md) defines the project's vocabulary: Token,
  Capability, Approver, Unrestricted, Required, Permissive, Caller Origin and
  the rest. Issues and reviews use these words with these meanings.
- [`docs/caller-origin-and-cidr.md`](docs/caller-origin-and-cidr.md) is the
  design for origin resolution, the CIDR approver and capability warnings,
  including the decision table for each mode.
- [`docs/adr/`](docs/adr/) records design decisions and the alternatives
  that were rejected.
- [pkg.go.dev](https://pkg.go.dev/github.com/xmidt-org/bascule) has the full
  API reference, with the same examples shown next to the types they use.

## Versioning

Bascule follows semantic versioning. Versions `v1.3.0` through `v1.3.5` are
retracted: they carried unintended breaking changes to the API and, more
seriously, to what a Token was authorized to reach. Go tooling will not select
them. See the comment in [`go.mod`](go.mod) for the details.

## Code of Conduct

This project and everyone participating in it are governed by the
[XMiDT Code Of Conduct](https://xmidt.io/code_of_conduct/). By participating,
you agree to this Code.

## Contributing

Refer to [CONTRIBUTING.md](CONTRIBUTING.md).
