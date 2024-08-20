// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
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

	// DefaultWildcardMethod is one of the default method strings that will match any HTTP method.
	DefaultWildcardMethod = "*"
)

var (
	// ErrMissingCapabilities indicates that a token had no capabilities
	// and thus is unauthorized.
	ErrMissingCapabilities = errors.New("no capabilities in token")
)

// urlPathNormalization ensures that the given URL has a leading slash.
func urlPathNormalization(url string) string {
	if url[0] == '/' {
		return url
	}

	return "/" + url
}

// CapabilityUnauthorizedError indicates that a given capability was
// rejected and the token is unauthorized.
type CapabilityUnauthorizedError struct {
	// Match is the match string in <prefix><url pattern>:<method> format
	// that matched the capability but did not match the resource request.
	Match string

	// Capability is the capability string from the token that was rejected.
	Capability string

	// Err is any error that occurred.  This will be returned from Unwrap.
	Err error
}

func (cue *CapabilityUnauthorizedError) Unwrap() error {
	return cue.Err
}

func (cue *CapabilityUnauthorizedError) StatusCode() int {
	return http.StatusForbidden
}

func (cue *CapabilityUnauthorizedError) Error() string {
	var o strings.Builder
	o.WriteString(`Capability [`)
	o.WriteString(cue.Capability)
	o.WriteString(`] was rejected due to [`)
	o.WriteString(cue.Match)
	o.WriteRune(']')

	if cue.Err != nil {
		o.WriteString(`: `)
		o.WriteString(cue.Err.Error())
	}

	return o.String()
}

// CapabilityApproverOption is a configurable option used to create a CapabilityApprover.
type CapabilityApproverOption interface {
	apply(*CapabilityApprover) error
}

type capabilityApproverOptionFunc func(*CapabilityApprover) error

func (caof capabilityApproverOptionFunc) apply(ca *CapabilityApprover) error { return caof(ca) }

// WithCapabilityPrefixes adds several prefixes used to match capabilities, e.g. x1:webpa:foo:.  Only
// the first prefix found during matching is considered for authorization.  If no prefixes
// are set via this option, the resulting approver will not authorize any requests.
//
// Note that a prefix can itself be a regular expression, but may not have any subexpressions.
func WithCapabilityPrefixes(prefixes ...string) CapabilityApproverOption {
	return capabilityApproverOptionFunc(func(ca *CapabilityApprover) error {
		for _, p := range prefixes {
			re, err := regexp.Compile("^" + p + "(.+):(.+?)$")
			switch {
			case err != nil:
				return fmt.Errorf("Unable to compile capability prefix [%s]: %s", p, err)

			case re.NumSubexp() != 2:
				return fmt.Errorf("The prefix [%s] cannot have subexpressions", p)

			default:
				ca.matchers = append(ca.matchers, re)
			}
		}

		return nil
	})
}

// WithCapabilityAllMethods changes the values used to signal a match of all HTTP methods.
// By default, both DefaultAllMethod and DefaultWildcardMethod, if present in a capability,
// will match any HTTP method.  This option overwrites the default, and is cumulative.
// However, a caller can add values to the default by using
// WithCapabilityAllMethods(DefaultAllMethod, DefaultWildcardMethod, "myvalue", ...).
func WithCapabilityAllMethods(v ...string) CapabilityApproverOption {
	return capabilityApproverOptionFunc(func(ca *CapabilityApprover) error {
		if ca.allMethods == nil {
			ca.allMethods = make(map[string]bool, len(v))
		}

		for _, matchAll := range v {
			ca.allMethods[matchAll] = true
		}

		return nil
	})
}

// CapabilityApprover is a bascule HTTP approver that authorizes tokens
// with capabilities against requests.
//
// This approver expects capabilities in tokens to be of the form <prefix><endpoing regex>:<method>.
//
// The allowed prefixes must be set via one or more WithCapabilityPrefixes options.  Prefixes
// may themselves contain colon delimiters and can be regular expressions without subexpressions.
type CapabilityApprover struct {
	matchers   []*regexp.Regexp
	allMethods map[string]bool
}

// NewCapabilityApprover creates a CapabilityApprover using the supplied options.
// At least (1) of the configured prefixes must match an HTTP request's URL in
// ordered for a token to be authorized.
//
// If no prefixes are added via WithCapabilityPrefix, then the returned approver
// will not authorize any requests.
func NewCapabilityApprover(opts ...CapabilityApproverOption) (ca *CapabilityApprover, err error) {
	ca = new(CapabilityApprover)
	for _, o := range opts {
		err = multierr.Append(err, o.apply(ca))
	}

	switch {
	case err != nil:
		ca = nil

	default:
		if len(ca.allMethods) == 0 {
			// enforce the defaults
			ca.allMethods = map[string]bool{
				DefaultAllMethod:      true,
				DefaultWildcardMethod: true,
			}
		}
	}

	return
}

// Approve attempts to match each capability to a configured prefix. Then, for any matched prefix,
// the URL regexp and method in the capability must match the resource.  URLs are normalized
// with a leading '/'.
//
// This method returns success (i.e. a nil error) when the first matching capability is found.
func (ca *CapabilityApprover) Approve(_ context.Context, resource *http.Request, token bascule.Token) error {
	capabilities, ok := bascule.GetCapabilities(token)
	if len(capabilities) == 0 || !ok {
		return ErrMissingCapabilities
	}

	for _, matcher := range ca.matchers {
		for _, capability := range capabilities {
			substrings := matcher.FindStringSubmatch(capability)
			if len(substrings) < 2 {
				// no match
				continue
			}

			// the format of capabilities is <prefix><url pattern>:<method>
			// <url pattern> and <method> will be substrings
			err := ca.approveURL(resource, substrings[1])
			if err == nil {
				err = ca.approveMethod(resource, substrings[2])
			}

			if err != nil {
				err = &CapabilityUnauthorizedError{
					Match:      matcher.String(),
					Capability: capability,
					Err:        err,
				}
			}

			// stop at the first match, regardless of result
			return err
		}
	}

	// none of the matchers matched any capability, OR there were no matchers configured
	return bascule.ErrUnauthorized
}

func (ca *CapabilityApprover) approveMethod(resource *http.Request, capabilityMethod string) error {
	switch {
	case ca.allMethods[capabilityMethod]:
		return nil

	case capabilityMethod == strings.ToLower(resource.Method):
		return nil

	default:
		return fmt.Errorf("method does not match request method [%s]", resource.Method)
	}
}

func (ca *CapabilityApprover) approveURL(resource *http.Request, capabilityURL string) error {
	resourcePath := resource.URL.EscapedPath()

	re, err := regexp.Compile(urlPathNormalization(capabilityURL))
	if err != nil {
		return err
	}

	indices := re.FindStringIndex(urlPathNormalization(resourcePath))
	if len(indices) < 1 || indices[0] != 0 {
		return fmt.Errorf("url does not match request URL [%s]", resourcePath)
	}

	return nil
}
