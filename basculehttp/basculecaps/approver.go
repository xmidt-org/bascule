// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculecaps

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
func WithPrefixes(prefixes ...string) ApproverOption {
	return approverOptionFunc(func(a *Approver) error {
		for _, p := range prefixes {
			re, err := regexp.Compile("^" + p + "(.+):(.+?)$")
			switch {
			case err != nil:
				return fmt.Errorf("Unable to compile capability prefix [%s]: %s", p, err)

			case re.NumSubexp() != 2:
				return fmt.Errorf("The prefix [%s] cannot have subexpressions", p)

			default:
				a.matchers = append(a.matchers, re)
			}
		}

		return nil
	})
}

// WithAllMethod changes the value used to signal a match of all HTTP methods.
// By default, DefaultAllMethod is used.
func WithAllMethod(allMethod string) ApproverOption {
	return approverOptionFunc(func(a *Approver) error {
		if len(allMethod) == 0 {
			return errors.New("the all method expression cannot be blank")
		}

		a.allMethod = allMethod
		return nil
	})
}

// Approver is a bascule HTTP approver that authorizes tokens
// with capabilities against requests.
//
// This approver expects capabilities in tokens to be of the form <prefix><endpoing regex>:<method>.
//
// The allowed prefixes must be set via one or more WithCapabilityPrefixes options.  Prefixes
// may themselves contain colon delimiters and can be regular expressions without subexpressions.
type Approver struct {
	matchers  []*regexp.Regexp
	allMethod string
}

// NewApprover creates a Approver using the supplied options. At least (1) of the configured
// prefixes must match an HTTP request's URL in ordered for a token to be authorized.
//
// If no prefixes are added via WithPrefixes, then the returned approver
// will not authorize any requests.
func NewApprover(opts ...ApproverOption) (a *Approver, err error) {
	a = new(Approver)
	for _, o := range opts {
		err = multierr.Append(err, o.apply(a))
	}

	switch {
	case err != nil:
		a = nil

	default:
		if len(a.allMethod) == 0 {
			a.allMethod = DefaultAllMethod
		}
	}

	return
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
			substrings := matcher.FindStringSubmatch(capability)
			if len(substrings) < 2 {
				// no match
				continue
			}

			// the format of capabilities is <prefix><url pattern>:<method>
			// <url pattern> and <method> will be substrings
			err := a.approveURL(resource, substrings[1])
			if err == nil {
				err = a.approveMethod(resource, substrings[2])
			}

			if err == nil {
				// success!
				return nil
			}
		}
	}

	return bascule.ErrUnauthorized
}

func (a *Approver) approveMethod(resource *http.Request, capabilityMethod string) error {
	switch {
	case a.allMethod == capabilityMethod:
		return nil

	case capabilityMethod == strings.ToLower(resource.Method):
		return nil

	default:
		return fmt.Errorf("method does not match request method [%s]", resource.Method)
	}
}

func (a *Approver) approveURL(resource *http.Request, capabilityURL string) error {
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
