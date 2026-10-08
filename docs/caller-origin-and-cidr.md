<!--
SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
SPDX-License-Identifier: Apache-2.0
-->

# Caller Origin and CIDR Capabilities

> **Status:** implemented in `basculehttp/origin.go`,
> `basculehttp/cidr.go` and `warning.go`. Terms are defined in
> [CONTEXT.md](../CONTEXT.md); the opt-in decision is in
> [ADR 0001](adr/0001-cidr-capabilities-are-opt-in.md).

Two features for `basculehttp`:

1. **Caller Origin**: work out the real client address of a request that
   may have passed through the deployment's own proxies.
2. **CIDR Approver**: an `Approver[*http.Request]` that requires the Caller
   Origin to fall inside a network range carried by the Token.

The first is useful on its own (logging, rate limiting) and is what the
second uses.

## Out of scope

- **Rate limiting.** Lives in a separate library.
- **TR-181 parameter checks.** Live in tr1d1um.
- **A shared "capability kind" framework.** Each Approver is independent and
  owns its own prefix, parsing, malformed handling, Required and
  Permissive behavior. Don't build a registry of kinds.

## 1. Caller Origin

### Behavior

Configured with a list of **Trusted Proxy** networks (CIDRs). Given a
request:

1. Let `peer` = the address from `request.RemoteAddr`.
2. If `peer` is not a Trusted Proxy, the Caller Origin is `peer`. Forwarding
   headers are ignored, because anyone can set them.
3. Otherwise, build the hop list from the `for=` parameters of the
   `Forwarded` header (RFC 7239). Use `X-Forwarded-For` only if there is no
   `Forwarded` header, or if no `Forwarded` element has a `for=` parameter
   (e.g. only `proto=https`). Walk the hops **right to left**, skipping
   Trusted Proxies. The first hop that isn't a Trusted Proxy is the Caller
   Origin.
4. If the hop list is empty (no usable forwarding header), the Caller Origin
   is **unknown**. A Trusted Proxy is expected to forward, so a missing
   header suggests misconfiguration; don't fall back to `peer`.
5. If every hop is trusted, the Caller Origin is the left-most hop.
6. If a hop the walk needs can't be parsed (e.g. `for=unknown`, an
   obfuscated identifier, or garbage), stop: the Caller Origin is
   **unknown** and must not match any CIDR.

Normalization:

- IPv4-mapped IPv6 (`::ffff:1.2.3.4`) becomes IPv4.
- Strip ports. `Forwarded` allows `for="[2001:db8::1]:4711"` and
  `for="1.2.3.4:80"`. Unquote, remove brackets, drop the port.
- Strip IPv6 zones.
- Multiple header lines and comma-separated values are concatenated in
  order.

With no Trusted Proxies configured, the Caller Origin is always
`request.RemoteAddr`.

### Suggested API

```go
// OriginResolver finds the Caller Origin of a request.
type OriginResolver struct{ /* trusted proxies */ }

func NewOriginResolver(opts ...OriginOption) (*OriginResolver, error)
func WithTrustedProxies(cidrs ...netip.Prefix) OriginOption

// Origin returns the Caller Origin. ok is false when it can't be determined.
func (r *OriginResolver) Origin(*http.Request) (addr netip.Addr, ok bool)
```

Use `net/netip` throughout.

## 2. CIDR Approver

### Capability format

`{prefix}<network>/<bits>`, e.g. `prefix:cidr:96.44.169.0/24`,
`prefix:cidr:2001:db8::/32`.

- The prefix works exactly like `basculecaps.WithPrefixes`: a string or
  regular expression, which may contain subexpressions. The remainder after
  the prefix is the network.
- The remainder must parse with `netip.ParsePrefix`. A bare address (no
  `/bits`) is **malformed**: a single host must be written `/32` or `/128`.
- IPv4-mapped IPv6 prefixes are normalized like origins.

### Modes

The Approver runs in exactly one of four modes. Two settings make them up:
whether a CIDR capability must be present (**Required**) or only checked
when present (**Correct If Present**), and whether a failure rejects
(**Enforcing**) or only warns (**Permissive**).

| Mode | Option | No CIDR capability | Malformed, or origin not matched / unknown |
|---|---|---|---|
| Required | `WithCIDRRequired()` | **reject** | **reject** |
| Correct If Present (default) | `WithCIDRCorrectIfPresent()` | **allow** (Unrestricted) | **reject** |
| Permissive Required | `WithCIDRPermissiveRequired()` | **allow** + warning | **allow** + warning |
| Permissive Correct If Present | `WithCIDRPermissiveCorrectIfPresent()` | **allow** (Unrestricted) | **allow** + warning |

Permissive Required is a trial run of Required: it reports every Token that
Required would reject without blocking any.

### Decision table

Evaluate on every request:

| Token's CIDR capabilities (after prefix selection) | Result |
|---|---|
| none, Correct If Present | **allow** (Unrestricted) |
| none, Required | **fail** |
| ≥1, Caller Origin unknown | **fail** |
| ≥1, origin inside any well-formed one | **allow** |
| ≥1, origin inside none (malformed ones match nothing) | **fail** |

Then:

- **Fail + Enforcing** → return an error wrapping `bascule.ErrUnauthorized`
  (so `DefaultErrorStatusCoder` gives `403`) plus a specific sentinel
  (`ErrNoCIDRCapability`, `ErrOriginNotAllowed`, `ErrUnknownOrigin`).
- **Fail + Permissive** → return `nil` and emit a Capability Warning saying
  what would have been rejected.
- **Every Malformed Capability** → emit a Capability Warning in every mode,
  **whether or not the request is allowed**. A typo masked by another valid
  CIDR must still be reported.

### Suggested API

```go
func NewCIDRApprover(opts ...CIDRApproverOption) (*CIDRApprover, error)

func WithCIDRPrefixes(prefixes ...string) CIDRApproverOption // required; none = error from New
func WithOriginResolver(*OriginResolver) CIDRApproverOption // default: RemoteAddr only
func WithCIDRCacheSize(size int) CIDRApproverOption         // default: DefaultCIDRCacheSize

// Mode options. Each sets the whole mode; if several are passed, the last
// one applied wins. Default: WithCIDRCorrectIfPresent.
func WithCIDRRequired() CIDRApproverOption
func WithCIDRCorrectIfPresent() CIDRApproverOption
func WithCIDRPermissiveRequired() CIDRApproverOption
func WithCIDRPermissiveCorrectIfPresent() CIDRApproverOption

func (a *CIDRApprover) Approve(ctx context.Context, r *http.Request, t bascule.Token) error
```

Capabilities come from tokens, so the result of matching each one against
the prefixes and parsing its network is kept in a bounded cache, like
the bounded cache in `internal/boundedcache`, which `basculecaps`'s URL cache also uses.

## 3. Capability Warnings (new plumbing)

`Approver.Approve` can only return an error, so warnings need a new path.
Design:

- The collector lives in the root `bascule` package (`warning.go`), not in
  `basculehttp`, because `bascule.Authorizer` builds `AuthorizeEvent` and
  can't import `basculehttp`.
- `basculehttp.Middleware` puts a collector in the request context
  (`bascule.WithWarnings`) **before** calling the Authenticator, so it also
  covers authentication and the protected handler's context.
- Approvers call `bascule.AddWarning(ctx, bascule.Warning{...})`. When there
  is no collector it does nothing, so Approvers still work outside the
  middleware. `bascule.GetWarnings(ctx)` returns a copy of what was
  collected.
- The middleware writes the collected warnings as response headers, one
  header per warning, on **both** the error path and the success path
  (before calling the protected handler).
- The header name is configured on the middleware
  (`WithWarningHeader(name)`). If it isn't set, nothing is written; bascule
  is not WebPA-specific, so don't hard-code `X-Webpa-…`. tr1d1um configures
  `X-Webpa-Capability-Warning`.
- Warning text format: `<reason>; key=value; …`. A value that is an HTTP
  token is written bare; anything else is quoted. The CIDR Approver writes:

  ```text
  malformed; kind=cidr; cap="prefix:cidr:10.0.0.0/33"
  would-reject; kind=cidr; reason=no-cidr-capability
  would-reject; kind=cidr; reason=unknown-origin
  would-reject; kind=cidr; reason=origin-not-allowed; origin=203.0.113.5
  ```

- Quoted values come from signed Tokens or the request, so they aren't
  treated as hostile, and `net/http` already strips CR/LF from header
  values. Only escape `"` and `\` with a backslash, so an issuer's typo
  can't break the `key="value"` format.

- The warnings are also in `AuthorizeEvent.Warnings`, so listeners (metrics, logs)
  see Permissive would-rejects even though `Err` is nil.

Other packages (tr1d1um's parameter checks, the rate library) should use the
same `AddWarning` call, so this is the one shared piece.

## Acceptance tests

Table-driven, testify, matching the repo's existing style.

Caller Origin:

- No trusted proxies → `RemoteAddr`, headers ignored.
- An untrusted peer sending a `Forwarded` header → `RemoteAddr` (spoof
  ignored).
- Trusted peer, `Forwarded: for=192.0.2.60;proto=http, for=10.0.0.1` with
  `10.0.0.0/8` trusted → `192.0.2.60`.
- Trusted peer, no `Forwarded`, `X-Forwarded-For: 192.0.2.60, 10.0.0.1` →
  `192.0.2.60`.
- Both headers present → `Forwarded` wins.
- Trusted peer, `Forwarded: proto=https` (no `for=`),
  `X-Forwarded-For: 192.0.2.60` → `192.0.2.60`.
- Trusted peer, no forwarding headers → not ok.
- Trusted peer, `Forwarded` without `for=` and no `X-Forwarded-For` → not
  ok.
- Quoted IPv6 with port, `for="[2001:db8::1]:4711"` → `2001:db8::1`.
- `::ffff:192.0.2.1` → `192.0.2.1`.
- `for=unknown` in the walk → not ok.
- All hops trusted → left-most.

CIDR Approver: every row of the decision table in all four modes, plus:

- No mode option → Correct If Present.
- Several mode options → the last one applied wins.
- Permissive Required with no CIDR capability → allowed, and a
  `no-cidr-capability` warning is emitted.
- Permissive Correct If Present with no CIDR capability → allowed, no
  warning.

- A malformed capability alongside a valid matching one → allowed, and a
  warning is emitted.
- Only a malformed capability → fails (not Unrestricted).
- A bare IP → malformed.
- IPv4 origin against an IPv6 prefix, and the reverse → no match.
- Capabilities with other prefixes are ignored and produce no warning.
- A regex prefix with subexpressions still yields the right network.

Warnings: emitted on a `403` and on a `200`; no header written when no
header name is configured; `AddWarning` with no collector doesn't panic;
a capability containing `"` or `\` is backslash-escaped in the header.
