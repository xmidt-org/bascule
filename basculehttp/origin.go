// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// OriginOption is a configurable option used to create an OriginResolver.
type OriginOption interface {
	apply(*OriginResolver) error
}

type originOptionFunc func(*OriginResolver) error

func (oof originOptionFunc) apply(r *OriginResolver) error { return oof(r) }

// WithTrustedProxies adds networks whose hops are Trusted Proxies, i.e. hops the
// deployment operates, such as load balancers, and trusts to report the address
// they received a request from.  Multiple calls are cumulative.
//
// This must always come from deployment configuration, never from a token.
func WithTrustedProxies(cidrs ...netip.Prefix) OriginOption {
	return originOptionFunc(func(r *OriginResolver) error {
		for _, p := range cidrs {
			if !p.IsValid() {
				return fmt.Errorf("invalid trusted proxy network [%s]", p)
			}

			r.trusted = append(r.trusted, normalizePrefix(p))
		}

		return nil
	})
}

// OriginResolver finds the Caller Origin of a request: the nearest hop that is
// not a Trusted Proxy.
//
// If the request's peer, i.e. its RemoteAddr, is not a Trusted Proxy, the peer
// is the Caller Origin and forwarding headers are ignored, since anyone can set
// them.  Otherwise, the hops reported by the Forwarded header (RFC 7239) are
// walked from right to left, skipping Trusted Proxies.  X-Forwarded-For is used
// instead only when no Forwarded element has a for= parameter.
//
// The zero value has no Trusted Proxies, so its Caller Origin is always the
// request's RemoteAddr.  An OriginResolver is safe for concurrent use.
type OriginResolver struct {
	trusted []netip.Prefix
}

// NewOriginResolver creates an OriginResolver from the supplied options.
func NewOriginResolver(opts ...OriginOption) (*OriginResolver, error) {
	var r OriginResolver

	var errs []error
	for _, o := range opts {
		if err := o.apply(&r); err != nil {
			errs = append(errs, err)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return &r, nil
}

// Origin returns the Caller Origin of a request.  IPv4-mapped IPv6 addresses
// are returned as IPv4, and IPv6 zones are removed.
//
// ok is false when the Caller Origin cannot be determined: the RemoteAddr
// cannot be parsed, the peer is a Trusted Proxy but forwarded no hops, or a hop
// the walk needs cannot be parsed (e.g. for=unknown or an obfuscated identifier).
func (r *OriginResolver) Origin(request *http.Request) (addr netip.Addr, ok bool) {
	peer, ok := parseRemoteAddr(request.RemoteAddr)
	if !ok || !r.isTrusted(peer) {
		return peer, ok
	}

	hops := forwardedHops(request.Header)
	if len(hops) == 0 {
		hops = xForwardedForHops(request.Header)
	}

	// a Trusted Proxy is expected to forward, so no hops means misconfiguration
	if len(hops) == 0 {
		return netip.Addr{}, false
	}

	for _, hop := range slices.Backward(hops) {
		addr, ok = parseNode(hop)
		if !ok {
			return netip.Addr{}, false
		}

		if !r.isTrusted(addr) {
			return addr, true
		}
	}

	// every hop is trusted, so the left-most is the best we know
	return addr, true
}

func (r *OriginResolver) isTrusted(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// forwardedHops returns the for= values of every Forwarded element, in order.
func forwardedHops(h http.Header) (hops []string) {
	for _, line := range h.Values("Forwarded") {
		for _, element := range splitQuoted(line, ',') {
			for _, pair := range splitQuoted(element, ';') {
				key, value, found := strings.Cut(pair, "=")
				if found && strings.EqualFold(strings.TrimSpace(key), "for") {
					hops = append(hops, strings.TrimSpace(value))
				}
			}
		}
	}

	return
}

// xForwardedForHops returns the entries of every X-Forwarded-For header, in order.
func xForwardedForHops(h http.Header) (hops []string) {
	for _, line := range h.Values("X-Forwarded-For") {
		for hop := range strings.SplitSeq(line, ",") {
			hops = append(hops, strings.TrimSpace(hop))
		}
	}

	return
}

// splitQuoted splits s on sep, ignoring any sep inside a quoted string.
func splitQuoted(s string, sep byte) (parts []string) {
	var (
		start   int
		quoted  bool
		escaped bool
	)

	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case !quoted && c == sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}

	return append(parts, s[start:])
}

// unquote removes the quotes and backslash escapes of a quoted string.  A value
// that is not quoted is returned as is.
func unquote(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}

	v = v[1 : len(v)-1]
	if strings.IndexByte(v, '\\') < 0 {
		return v
	}

	var o strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}

		o.WriteByte(v[i])
	}

	return o.String()
}

// parseRemoteAddr parses an http.Request's RemoteAddr, which is normally
// host:port but may be a bare address.
func parseRemoteAddr(v string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return normalizeAddr(ap.Addr()), true
	}

	return parseNode(v)
}

// parseNode parses one hop of a forwarding header, e.g. 192.0.2.60,
// "192.0.2.60:80", or "[2001:db8::1]:4711".  Any port is dropped.
func parseNode(v string) (netip.Addr, bool) {
	v = unquote(v)

	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end < 0 || (end+1 < len(v) && v[end+1] != ':') {
			return netip.Addr{}, false
		}

		v = v[1:end]
	} else if strings.Count(v, ":") == 1 {
		// IPv4 with a port; a bare IPv6 address has more than one colon
		v, _, _ = strings.Cut(v, ":")
	}

	addr, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Addr{}, false
	}

	return normalizeAddr(addr), true
}

// normalizeAddr converts an IPv4-mapped IPv6 address to IPv4 and drops any zone.
func normalizeAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// normalizePrefix converts an IPv4-mapped IPv6 network to IPv4 and masks off
// any host bits.  A network that is only partly IPv4-mapped stays IPv6.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}

	return p.Masked()
}
