// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/xmidt-org/bascule"
)

const (
	// DefaultAllMethod is one of the default method strings that will match any HTTP method.
	DefaultAllMethod = "all"
)

// ApproverOption is a configurable option used to create an Approver.
type ApproverOption interface {
	apply(*Approver) error
}

type approverOptionFunc func(*Approver) error

func (aof approverOptionFunc) apply(a *Approver) error { return aof(a) }

// WithPrefixes adds several prefixes used to match capabilities, e.g. x1:webpa:foo:.
// If no prefixes are set via this option, the approver rejects all tokens.
//
// Note that a prefix can itself be a regular expression, and may contain
// subexpressions.
func WithPrefixes(prefixes ...string) ApproverOption {
	return approverOptionFunc(func(a *Approver) error {
		for _, p := range prefixes {
			// Group the prefix so that a top-level alternation cannot escape
			// the anchor or the subexpressions that follow it.  The prefix may
			// contain subexpressions of its own; since they are all opened
			// before the two below, the url and method are always the last two.
			re, err := regexp.Compile("^(?:" + p + ")(.+):(.+?)$")
			if err != nil {
				return fmt.Errorf("Unable to compile capability prefix [%s]: %s", p, err)
			}

			a.matchers = append(a.matchers, re)
		}

		return nil
	})
}

// WithCacheSize sets how many compiled capability url patterns an Approver
// retains.  By default, DefaultCacheSize is used.  The size must be positive.
//
// Capability url patterns arrive on tokens rather than from configuration, so
// this cache is bounded.  Once it is full the entry added longest ago is
// evicted; reading an entry does not protect it.  A token presenting a large
// number of distinct patterns will therefore evict the patterns in everyday
// use, costing each of those a recompile when it is next seen.  It cannot grow
// the cache beyond this size.
func WithCacheSize(size int) ApproverOption {
	return approverOptionFunc(func(a *Approver) error {
		if size < 1 {
			return errors.New("the url cache size must be positive")
		}

		a.cacheSize = size
		return nil
	})
}

// WithAllMethod changes the value used to signal a match of all HTTP methods.
// By default, DefaultAllMethod is used.
func WithAllMethod(allMethod string) ApproverOption {
	return approverOptionFunc(func(a *Approver) error {
		if allMethod == "" {
			return errors.New("the all method expression cannot be blank")
		}

		a.allMethod = allMethod
		return nil
	})
}

// WithURLNormalizeFunc sets a function that rewrites a request's URL before its
// path is matched against a capability.  By default the URL is used as it
// arrived.
//
// This is for deployments whose paths carry something capabilities are not
// written against, such as an api version: strip /api/v1 here and a capability
// may be written test/.* rather than .*/test/.*.  Since every capability is
// matched against the result, a normalization that removes too much widens
// every token at once.
//
// The URL is passed and returned by value, so a function may modify what it is
// given without affecting the request the handlers below will see.
func WithURLNormalizeFunc(fn func(url.URL) url.URL) ApproverOption {
	return approverOptionFunc(func(a *Approver) error {
		if fn == nil {
			return errors.New("the url normalize function cannot be nil")
		}

		a.normalizeURL = fn
		return nil
	})
}

// urlIdentityFunc is the default normalization function where nothing is changed.
func urlIdentityFunc(u url.URL) url.URL {
	return u
}

// Approver is a bascule HTTP approver that authorizes tokens
// with capabilities against requests.
//
// This approver expects capabilities in tokens to be of the form <prefix><endpoint regex>:<method>.
//
// The allowed prefixes must be set via one or more WithPrefixes options.  Prefixes
// may themselves contain colon delimiters, and can be regular expressions that
// contain subexpressions.
type Approver struct {
	matchers  []*regexp.Regexp
	allMethod string
	cacheSize int

	// normalizeURL rewrites a request's URL before its path is matched.  It is
	// nil unless WithURLNormalizeFunc was used.
	normalizeURL func(url.URL) url.URL

	// urlCache holds capability url patterns compiled by approveURL.  Patterns
	// come from tokens rather than from configuration, so they cannot be
	// compiled up front.
	urlCache *urlCache
}

// NewApprover creates a Approver using the supplied options. At least (1) of the configured
// prefixes must match an HTTP request's URL in ordered for a token to be authorized.
//
// If no prefixes are added via WithPrefixes, then the returned approver
// will not authorize any requests.
func NewApprover(opts ...ApproverOption) (*Approver, error) {
	a := Approver{
		cacheSize:    DefaultCacheSize,
		allMethod:    DefaultAllMethod,
		normalizeURL: urlIdentityFunc,
	}

	var errs []error
	for _, o := range opts {
		if err := o.apply(&a); err != nil {
			errs = append(errs, err)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	a.urlCache = newURLCache(a.cacheSize)

	return &a, nil
}

// Approve attempts to match each of the token's capabilities to a configured prefix.
// Then, for any matched prefix, the URL regexp and method carried by that capability
// must match the resource.  The request's path is normalized with a leading '/', and
// the capability's URL regexp must match it from the beginning.
//
// This method returns success (i.e. a nil error) when the first matching capability is found.  If
// the token provided no capabilities, or if none of the token's capabilities authorized the request,
// this method returns an error joined with bascule.ErrUnauthorized.
//
// That error also says why.  A denial is always ErrNoMatchingCapability; when
// the token carried no capabilities at all it is additionally ErrNoCapabilities,
// so a caller may ask the broad question or the narrow one.
func (a *Approver) Approve(_ context.Context, resource *http.Request, token bascule.Token) error {
	capabilities, _ := bascule.GetCapabilities(token)
	if len(capabilities) == 0 {
		return errors.Join(bascule.ErrUnauthorized, ErrNoMatchingCapability, ErrNoCapabilities)
	}

	for _, matcher := range a.matchers {
		for _, capability := range capabilities {
			substrings := matcher.FindStringSubmatch(capability)
			if len(substrings) < 3 {
				// no match
				continue
			}

			// the format of capabilities is <prefix><url pattern>:<method>
			// <url pattern> and <method> are the last two subexpressions, after
			// any the prefix itself contributed
			err := a.approveURL(resource, substrings[len(substrings)-2])
			if err == nil {
				err = a.approveMethod(resource, substrings[len(substrings)-1])
			}

			if err == nil {
				// success!
				return nil
			}
		}
	}

	return errors.Join(bascule.ErrUnauthorized, ErrNoMatchingCapability)
}

func (a *Approver) approveMethod(resource *http.Request, capabilityMethod string) error {
	if a.allMethod == capabilityMethod {
		return nil
	}

	if capabilityMethod == strings.ToLower(resource.Method) {
		return nil
	}

	return fmt.Errorf("method does not match request method [%s]", resource.Method)
}

func (a *Approver) approveURL(resource *http.Request, capabilityURL string) error {
	// The pattern is anchored as a whole.  Grouping keeps a top-level
	// alternation from escaping the anchor, and leaves the pattern itself
	// untouched -- a leading '/' cannot be added to a regex safely.
	re, err := a.urlCache.compile(capabilityURL)
	if err != nil {
		return err
	}

	// The URL is passed by value, so a normalization that modifies what it is
	// given cannot alter the request.
	normalized := a.normalizeURL(*resource.URL)
	path := normalized.EscapedPath()

	rooted := path
	if !strings.HasPrefix(rooted, "/") {
		rooted = "/" + rooted
	}
	unrooted := strings.TrimPrefix(rooted, "/")

	// Try the path both with and without its leading '/', so that a capability
	// may be written either way.  A path beginning with '//' is tried only
	// as-is, since dropping one slash would let /admin authorize //admin.
	candidates := make([]string, 1, 2)
	candidates[0] = rooted
	if !strings.HasPrefix(unrooted, "/") {
		candidates = append(candidates, unrooted)
	}

	for _, candidate := range candidates {
		if indices := re.FindStringIndex(candidate); len(indices) > 0 && indices[0] == 0 {
			return nil
		}
	}

	return fmt.Errorf("url does not match request URL [%s]", path)
}
