// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/internal/boundedcache"
	"github.com/xmidt-org/bascule/internal/prefix"
)

// The errors CIDRApprover.Approve returns.  Each is joined with
// bascule.ErrUnauthorized, so a caller that only cares whether the request was
// authorized is unaffected.
var (
	// ErrNoCIDRCapability indicates a Required CIDRApprover saw a token that
	// carried no CIDR capability.
	ErrNoCIDRCapability = errors.New("no cidr capability")

	// ErrOriginNotAllowed indicates the Caller Origin was inside none of the
	// token's CIDR capabilities.
	ErrOriginNotAllowed = errors.New("caller origin not allowed")

	// ErrUnknownOrigin indicates the token carried CIDR capabilities, but the
	// Caller Origin could not be determined.
	ErrUnknownOrigin = errors.New("unknown caller origin")

	// ErrCIDRDenied indicates the CIDRResolver returned an error.  That error
	// is joined too, for the service to log.
	ErrCIDRDenied = errors.New("cidr resolver denied the request")

	// ErrNoCIDRPrefixes is returned by NewCIDRApprover when no capability
	// prefixes were configured.
	ErrNoCIDRPrefixes = errors.New("at least one cidr capability prefix is required")
)

// DefaultCIDRCacheSize is the number of parsed capabilities a CIDRApprover
// retains by default.
const DefaultCIDRCacheSize = 1024

// cidrWarningKind identifies the warnings a CIDRApprover raises.
const cidrWarningKind = "cidr"

// CIDRApproverOption is a configurable option used to create a CIDRApprover.
type CIDRApproverOption interface {
	apply(*CIDRApprover) error
}

type cidrApproverOptionFunc func(*CIDRApprover) error

func (caof cidrApproverOptionFunc) apply(a *CIDRApprover) error { return caof(a) }

// WithCIDRPrefixLiterals adds the prefixes that select a token's CIDR
// capabilities, e.g. webpa-prefix-cidr:.  Each prefix is compared as written:
// every character, including ones that are regular expression metacharacters,
// must appear in the capability.  The remainder of a capability after its
// prefix is the network.  Multiple calls are cumulative.
//
// At least one prefix is required.  Capabilities matching no prefix are ignored.
func WithCIDRPrefixLiterals(prefixes ...string) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		for _, p := range prefixes {
			a.matchers = append(a.matchers, prefix.Literal(p))
		}

		return nil
	})
}

// WithCIDRPrefixRegexes adds the prefixes that select a token's CIDR
// capabilities, each a regular expression anchored at the start of the
// capability.  An expression may contain subexpressions and top-level
// alternation.  The remainder of a capability after its prefix is the network.
// Multiple calls are cumulative.
//
// Prefer WithCIDRPrefixLiterals unless an open-ended family of prefixes must
// be selected.  A literal prefix that happens to contain a metacharacter, such
// as foo-bar|, means something quite different as a regular expression.
//
// At least one prefix is required.  Capabilities matching no prefix are ignored.
func WithCIDRPrefixRegexes(prefixes ...string) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		for _, p := range prefixes {
			m, err := prefix.Regex(p)
			if err != nil {
				return err
			}

			a.matchers = append(a.matchers, m)
		}

		return nil
	})
}

// WithCIDRPrefixes adds the prefixes that select a token's CIDR capabilities,
// e.g. webpa-prefix-cidr:.  Each prefix is a regular expression, exactly as with
// WithCIDRPrefixRegexes.
//
// Deprecated: use WithCIDRPrefixLiterals for prefixes that should be matched
// as written, or WithCIDRPrefixRegexes for prefixes that are regular
// expressions.
func WithCIDRPrefixes(prefixes ...string) CIDRApproverOption {
	return WithCIDRPrefixRegexes(prefixes...)
}

// A CIDRResolver has the final say over the networks a token counts as
// carrying.  It is called on every request, with the request's context, the
// token's principal, which for a JWT is its sub claim, and the networks of the
// token's CIDR capabilities, in token order.  A malformed capability arrives
// as an invalid netip.Prefix, which contains nothing.
//
// Whatever the resolver returns is used instead, as if the token had carried
// those networks.  Returning no networks leaves the token Unrestricted, so it
// is allowed unless the approver is Required.  Returning an error denies the
// request with ErrCIDRDenied, whatever the reason: the error is joined for the
// service to log, and is not shown to the caller.  IPv4-mapped IPv6 networks
// are normalized to IPv4.
//
// That covers the policy a deployment needs, without an option for each case:
//
//   - Networks configured per principal, for an issuer that does not put
//     them in tokens: return append(provided, configured[principal]...).
//   - An override for one principal: ignore provided and return the override.
//   - A ceiling for every principal: drop any network not inside it.
//   - Requiring a network of some principals: return an error when provided
//     is empty for one of them.
//   - Blocking a principal: return an error.
//
// The resolver is trusted, so what it returns is not checked against the
// prefixes, and raises no warnings.  The malformed warnings for the provided
// networks are raised before the resolver runs, in every mode.
type CIDRResolver func(ctx context.Context, principal string, provided []netip.Prefix) ([]netip.Prefix, error)

// DefaultCIDRResolver is the CIDRResolver unless WithCIDRResolver says
// otherwise.  It returns the provided networks unchanged and never returns an
// error, so the token counts as carrying exactly its CIDR capabilities.
func DefaultCIDRResolver(_ context.Context, _ string, provided []netip.Prefix) ([]netip.Prefix, error) {
	return provided, nil
}

// WithCIDRResolver sets the CIDRResolver, replacing DefaultCIDRResolver.
func WithCIDRResolver(r CIDRResolver) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		if r == nil {
			return errors.New("the cidr resolver cannot be nil")
		}

		a.resolve = r
		return nil
	})
}

// WithOriginResolver sets how the Caller Origin of a request is found.  By
// default, it is always the request's RemoteAddr.
func WithOriginResolver(r *OriginResolver) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		if r == nil {
			return errors.New("the origin resolver cannot be nil")
		}

		a.resolver = r
		return nil
	})
}

// WithCIDRCacheSize sets how many parsed capabilities a CIDRApprover retains.
// By default, DefaultCIDRCacheSize is used.  The size must be positive.
//
// Capabilities arrive on tokens rather than from configuration, so this cache
// is bounded.  Once it is full the entry added longest ago is evicted.
func WithCIDRCacheSize(size int) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		if size < 1 {
			return errors.New("the cidr cache size must be positive")
		}

		a.cacheSize = size
		return nil
	})
}

// WithCIDRRequired rejects a token unless it carries at least one CIDR
// capability and the Caller Origin is inside one of them.
//
// The mode options each set the whole mode; if several are used, the last one
// applied wins.
func WithCIDRRequired() CIDRApproverOption {
	return withCIDRMode(true, false)
}

// WithCIDRCorrectIfPresent allows a token that carries no CIDR capability, i.e.
// is Unrestricted, but otherwise rejects it unless the Caller Origin is inside
// one of its CIDR capabilities.  This is the default mode.
//
// The mode options each set the whole mode; if several are used, the last one
// applied wins.
func WithCIDRCorrectIfPresent() CIDRApproverOption {
	return withCIDRMode(false, false)
}

// WithCIDRPermissiveRequired never rejects a request.  Instead, it raises a
// warning for every request that WithCIDRRequired would reject, so Required can
// be tried out before it is enforced.
//
// The mode options each set the whole mode; if several are used, the last one
// applied wins.
func WithCIDRPermissiveRequired() CIDRApproverOption {
	return withCIDRMode(true, true)
}

// WithCIDRPermissiveCorrectIfPresent never rejects a request.  Instead, it
// raises a warning for every request that WithCIDRCorrectIfPresent would reject.
//
// The mode options each set the whole mode; if several are used, the last one
// applied wins.
func WithCIDRPermissiveCorrectIfPresent() CIDRApproverOption {
	return withCIDRMode(false, true)
}

func withCIDRMode(required, permissive bool) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		a.required = required
		a.permissive = permissive
		return nil
	})
}

// CIDRApprover is a bascule HTTP approver that requires the Caller Origin of a
// request to be inside a network carried by the token, as a capability of the
// form <prefix><network>/<bits>, e.g. webpa-prefix-cidr:192.0.2.0/24.  A
// CIDRResolver may change the networks a token counts as carrying, for example
// to add networks configured for its principal.
//
// CIDR capabilities only limit access; they never grant it.  A capability whose
// network cannot be parsed, including a bare address without /bits, is
// malformed: it still counts as present, so the token is not Unrestricted, but
// matches nothing.  Every malformed capability raises a warning, whether or not
// the request is allowed.
type CIDRApprover struct {
	matchers   []prefix.Matcher
	resolve    CIDRResolver
	resolver   *OriginResolver
	required   bool
	permissive bool
	cacheSize  int

	// cache holds capabilities already matched against the prefixes and
	// parsed.  Capabilities come from tokens, so the cache is bounded.
	cache *boundedcache.Cache[cidrCapability]
}

// NewCIDRApprover creates a CIDRApprover from the supplied options.  At least
// one prefix must be supplied with WithCIDRPrefixLiterals or
// WithCIDRPrefixRegexes.
func NewCIDRApprover(opts ...CIDRApproverOption) (*CIDRApprover, error) {
	a := CIDRApprover{
		resolve:   DefaultCIDRResolver,
		resolver:  new(OriginResolver),
		cacheSize: DefaultCIDRCacheSize,
	}

	var errs []error
	for _, o := range opts {
		if err := o.apply(&a); err != nil {
			errs = append(errs, err)
		}
	}

	if len(a.matchers) == 0 {
		errs = append(errs, ErrNoCIDRPrefixes)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	a.cache = boundedcache.New[cidrCapability](a.cacheSize)

	return &a, nil
}

// Approve checks the Caller Origin of the request against the networks the
// token counts as carrying: its CIDR capabilities, as the CIDRResolver sees
// fit.  Warnings are raised with bascule.AddWarning.
//
// In an enforcing mode, a rejection is an error joined with
// bascule.ErrUnauthorized and one of ErrNoCIDRCapability, ErrUnknownOrigin,
// ErrOriginNotAllowed or ErrCIDRDenied.  In a permissive mode, this method
// never returns an error.
func (a *CIDRApprover) Approve(ctx context.Context, resource *http.Request, token bascule.Token) error {
	var principal string
	if token != nil {
		principal = token.Principal()
	}

	networks, err := a.resolve(ctx, principal, a.selectNetworks(ctx, token))
	if err != nil {
		return a.reject(ctx, errors.Join(ErrCIDRDenied, err), "denied")
	}

	if len(networks) == 0 {
		if !a.required {
			return nil
		}

		return a.reject(ctx, ErrNoCIDRCapability, "no-cidr-capability")
	}

	origin, ok := a.resolver.Origin(resource)
	if !ok {
		return a.reject(ctx, ErrUnknownOrigin, "unknown-origin")
	}

	for _, network := range networks {
		// an invalid network, from a malformed capability or the resolver,
		// contains nothing
		if normalizePrefix(network).Contains(origin) {
			return nil
		}
	}

	return a.reject(ctx, ErrOriginNotAllowed, "origin-not-allowed",
		bascule.WarningAttr{Key: "origin", Value: origin.String()},
	)
}

// reject returns err, or in a permissive mode, raises a warning with the given
// reason and attrs instead.
func (a *CIDRApprover) reject(ctx context.Context, err error, reason string, attrs ...bascule.WarningAttr) error {
	if !a.permissive {
		return errors.Join(bascule.ErrUnauthorized, err)
	}

	bascule.AddWarning(ctx, bascule.Warning{
		Reason: "would-reject",
		Attrs: append(
			[]bascule.WarningAttr{
				{Key: "kind", Value: cidrWarningKind},
				{Key: "reason", Value: reason},
			},
			attrs...,
		),
	})

	return nil
}

// selectNetworks returns the networks of the token's CIDR capabilities, in
// token order.  A malformed capability raises a warning and contributes an
// invalid netip.Prefix, so that it still counts as present.
func (a *CIDRApprover) selectNetworks(ctx context.Context, token bascule.Token) (networks []netip.Prefix) {
	capabilities, _ := bascule.GetCapabilities(token)
	for _, capability := range capabilities {
		parsed := a.parse(capability)
		if !parsed.selected {
			continue
		}

		if !parsed.network.IsValid() {
			bascule.AddWarning(ctx, bascule.Warning{
				Reason: "malformed",
				Attrs: []bascule.WarningAttr{
					{Key: "kind", Value: cidrWarningKind},
					{Key: "cap", Value: capability},
				},
			})
		}

		networks = append(networks, parsed.network)
	}

	return networks
}

// parse matches a capability against the prefixes and parses its network.
func (a *CIDRApprover) parse(capability string) cidrCapability {
	if parsed, ok := a.cache.Get(capability); ok {
		return parsed
	}

	var parsed cidrCapability
	for _, matcher := range a.matchers {
		rest, ok := matcher.Match(capability)
		if !ok || rest == "" {
			continue
		}

		parsed.selected = true
		if network, err := netip.ParsePrefix(rest); err == nil {
			parsed.network = normalizePrefix(network)
		}

		break
	}

	return a.cache.Add(capability, parsed)
}

// cidrCapability is the result of matching one capability against the prefixes.
type cidrCapability struct {
	// selected is true if a prefix matched the capability.
	selected bool

	// network is the capability's network.  It is invalid if the capability
	// was not selected or is malformed.
	network netip.Prefix
}
