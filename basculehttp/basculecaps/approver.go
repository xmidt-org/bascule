// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/xmidt-org/bascule"
	"go.uber.org/multierr"
)

const (
	// DefaultAllMethod is one of the default method strings that will match any HTTP method.
	DefaultAllMethod = "all"

	// ConfigurationMatcherRegex searches for the following three capability related groups:
	// 1) api scope (in the form of "string:string:string")
	// 2) url pattern
	// 3) method
	ConfigurationMatcherRegex = `^(\b(?:[^:]+:){2}[^:]+):([^:]+):([^:]+\b)$`
	MatcherRegex              = `(%s):(%s):(%s)`
)

// urlPathNormalization ensures that the given URL has a leading slash.
func urlPathNormalization(url string) string {
	if url[0] == '/' {
		return url
	}

	return "/" + url
}

// ApproverOption is a configurable option used to create an Approver.
type ApproverOption interface {
	apply(*Approver) error
}

type approverOptionFunc func(*Approver) error

func (aof approverOptionFunc) apply(a *Approver) error { return aof(a) }

// WithPrefixes adds several prefixes used to match capabilities, e.g. x1:webpa:foo:.
// If no prefixes are set via this option, the approver rejects all tokens.
//
// Note that a prefix can itself be a regular expression, but may not have any subexpressions.
func WithCapabilities(capabilities ...string) ApproverOption {
	regex := regexp.MustCompile(ConfigurationMatcherRegex)
	return approverOptionFunc(func(a *Approver) error {
		for _, cap := range capabilities {
			substrings := regex.FindStringSubmatch(cap)
			if len(substrings) < 4 {
				return fmt.Errorf("Expected %s have three components (api scope, url pattern and method) instead of %d", cap, len(substrings))
			}

			capRegex, err := regexp.Compile(fmt.Sprintf(MatcherRegex, substrings[1], substrings[2], substrings[3]))
			if err != nil {
				return fmt.Errorf("Unable to compile capability matcher %s: %v", cap, err)
			}

			urlRegex, err := regexp.Compile(substrings[2])
			if err != nil {
				return fmt.Errorf("Unable to compile url regex %s for the capability matcher %s: %v", substrings[2], cap, err)
			}

			a.matchers = append(a.matchers, matcher{
				capRegex: capRegex,
				urlRegex: urlRegex,
				method:   substrings[3],
			})
		}

		return nil
	})
}

// NewApprover creates a Approver using the supplied options. At least (1) of the configured
// prefixes must match an HTTP request's URL in ordered for a token to be authorized.
//
// If no prefixes are added via WithPrefixes, then the returned approver
// will not authorize any requests.
func NewApprover(opts ...ApproverOption) (*Approver, error) {
	a := Approver{}

	var errs error
	for _, o := range opts {
		errs = multierr.Append(errs, o.apply(&a))
	}

	return &a, errs
}

// Approve attempts to match each capability to a configured prefix. Then, for any matched prefix,
// the URL regexp and method in the capability must match the resource.  URLs are normalized
// with a leading '/'.
//
// This method returns success (i.e. a nil error) when the first matching capability is found.  If
// the token provided no capabilities, or if none of the token's capabilities authorized the request,
// this method returns bascule.ErrUnauthorized.
func (a *Approver) Approve(_ context.Context, resource *http.Request, token bascule.Token) error {
	capabilities, _ := bascule.GetCapabilities(token)
	for _, matcher := range a.matchers {
		for _, capability := range capabilities {
			// Does the user capability match any of the expected capabilities?
			// the format of capabilities is <prefix><url pattern>:<method>
			// <url pattern> and <method> subcomponents be substrings
			// TODO: this error should be added as an authorizer event metadata.
			if matcher.MustMatchhCapability(resource, capability) == nil {
				// success!
				return nil
			}
		}
	}

	return bascule.ErrUnauthorized
}

// Approver is a bascule HTTP approver that authorizes tokens
// with capabilities against requests.
//
// This approver expects capabilities in tokens to be of the form <prefix><endpoing regex>:<method>.
//
// The allowed prefixes must be set via one or more WithCapabilityPrefixes options.  Prefixes
// may themselves contain colon delimiters and can be regular expressions without subexpressions.
type Approver struct {
	matchers  []matcher
	allMethod string
}

type matcher struct {
	capRegex *regexp.Regexp
	urlRegex *regexp.Regexp
	method   string
}

func (m matcher) MustMatchhCapability(req *http.Request, cap string) error {
	substrings := m.capRegex.FindStringSubmatch(cap)
	if len(substrings) < 4 {
		// no match
		return fmt.Errorf("the request capability `%s` does not match the expected `%s`", cap, m.capRegex.String())
	}

	return multierr.Combine(m.matchStrinhg(cap), m.approveURL(req),
		m.approveMethod(req))
}

func (m matcher) matchStrinhg(cap string) error {
	substrings := m.capRegex.FindStringSubmatch(cap)
	if len(substrings) < 4 {
		return fmt.Errorf("the request capability `%s` does not match the expected `%s`", cap, m.capRegex.String())
	}

	return nil
}
func (m matcher) approveMethod(resource *http.Request) error {
	switch m.method {
	case DefaultAllMethod, strings.ToLower(resource.Method):
		return nil
	default:
		return fmt.Errorf("method does not match request method [%s]", resource.Method)
	}
}

func (m matcher) approveURL(resource *http.Request) error {
	resourcePath := resource.URL.EscapedPath()
	indices := m.urlRegex.FindStringIndex(urlPathNormalization(resourcePath))
	if len(indices) < 1 || indices[0] != 0 {
		return fmt.Errorf("url does not match request URL [%s]", resourcePath)
	}

	return nil
}
