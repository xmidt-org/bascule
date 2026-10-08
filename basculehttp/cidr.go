// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/internal/boundedcache"
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

// WithCIDRPrefixes adds the prefixes that select a token's CIDR capabilities,
// e.g. x1:webpa:cidr:.  A prefix may be a regular expression, and may contain
// subexpressions.  The remainder of a capability after its prefix is the
// network.  Multiple calls are cumulative.
//
// At least one prefix is required.  Capabilities matching no prefix are ignored.
func WithCIDRPrefixes(prefixes ...string) CIDRApproverOption {
	return cidrApproverOptionFunc(func(a *CIDRApprover) error {
		for _, p := range prefixes {
			// Group the prefix so that a top-level alternation cannot escape the
			// anchor.  Any subexpressions of the prefix are opened before the
			// network's, so the network is always the last.
			re, err := regexp.Compile("^(?:" + p + ")(.+)$")
			if err != nil {
				return fmt.Errorf("Unable to compile cidr capability prefix [%s]: %s", p, err)
			}

			a.matchers = append(a.matchers, re)
		}

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
// form <prefix><network>/<bits>, e.g. x1:webpa:cidr:192.0.2.0/24.
//
// CIDR capabilities only limit access; they never grant it.  A capability whose
// network cannot be parsed, including a bare address without /bits, is
// malformed: it still counts as present, so the token is not Unrestricted, but
// matches nothing.  Every malformed capability raises a warning, whether or not
// the request is allowed.
type CIDRApprover struct {
	matchers   []*regexp.Regexp
	resolver   *OriginResolver
	required   bool
	permissive bool
	cacheSize  int

	// cache holds capabilities already matched against the prefixes and
	// parsed.  Capabilities come from tokens, so the cache is bounded.
	cache *boundedcache.Cache[cidrCapability]
}

// NewCIDRApprover creates a CIDRApprover from the supplied options.  At least
// one prefix must be supplied with WithCIDRPrefixes.
func NewCIDRApprover(opts ...CIDRApproverOption) (*CIDRApprover, error) {
	a := CIDRApprover{
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

// Approve checks the Caller Origin of the request against the token's CIDR
// capabilities.  Warnings are raised with bascule.AddWarning.
//
// In an enforcing mode, a rejection is an error joined with
// bascule.ErrUnauthorized and one of ErrNoCIDRCapability, ErrUnknownOrigin or
// ErrOriginNotAllowed.  In a permissive mode, this method never returns an error.
func (a *CIDRApprover) Approve(ctx context.Context, resource *http.Request, token bascule.Token) error {
	capabilities, _ := bascule.GetCapabilities(token)

	var (
		present  bool
		networks []netip.Prefix
	)

	for _, capability := range capabilities {
		parsed := a.parse(capability)
		if !parsed.selected {
			continue
		}

		present = true
		if !parsed.network.IsValid() {
			bascule.AddWarning(ctx, bascule.Warning{
				Reason: "malformed",
				Attrs: []bascule.WarningAttr{
					{Key: "kind", Value: cidrWarningKind},
					{Key: "cap", Value: capability},
				},
			})

			continue
		}

		networks = append(networks, parsed.network)
	}

	if !present {
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
		if network.Contains(origin) {
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

// parse matches a capability against the prefixes and parses its network.
func (a *CIDRApprover) parse(capability string) cidrCapability {
	if parsed, ok := a.cache.Get(capability); ok {
		return parsed
	}

	var parsed cidrCapability
	for _, matcher := range a.matchers {
		substrings := matcher.FindStringSubmatch(capability)
		if len(substrings) < 2 {
			continue
		}

		parsed.selected = true
		if network, err := netip.ParsePrefix(substrings[len(substrings)-1]); err == nil {
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
