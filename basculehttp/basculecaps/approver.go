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

var (
	// ErrMissingCapabilities indicates that a token had no capabilities
	// and thus is unauthorized.
	ErrMissingCapabilities = &UnauthorizedError{
		Err: errors.New("no capabilities in token"),
	}
)

// urlPathNormalization ensures that the given URL has a leading slash.
func urlPathNormalization(url string) string {
	if url[0] == '/' {
		return url
	}

	return "/" + url
}

// UnauthorizedError indicates that a given capability was rejected and
// that the token is unauthorized.
type UnauthorizedError struct {
	// Match is the regular expression that matched the capability.
	// This will be unset if no match occurred, i.e. if there were
	// no capabilities in the token.
	Match string

	// Capability is the capability string from the token that was rejected.
	// This will be unset if there were no capabilities in the token.
	Capability string

	// Err is any error that occurred.  This is NOT returned by Unwrap.
	Err error
}

// Unwrap always returns bascule.ErrUnauthorized, even if the Err field is set.
func (ue *UnauthorizedError) Unwrap() error {
	return bascule.ErrUnauthorized
}

// StatusCode always returns http.StatusForbidden.
func (*UnauthorizedError) StatusCode() int {
	return http.StatusForbidden
}

func (ue *UnauthorizedError) Error() string {
	var o strings.Builder
	o.WriteString(`Capability [`)
	o.WriteString(ue.Capability)
	o.WriteString(`] was rejected due to [`)
	o.WriteString(ue.Match)
	o.WriteRune(']')

	if ue.Err != nil {
		o.WriteString(`: `)
		o.WriteString(ue.Err.Error())
	}

	return o.String()
}

// ApproverOption is a configurable option used to create an Approver.
type ApproverOption interface {
	apply(*Approver) error
}

type approverOptionFunc func(*Approver) error

func (aof approverOptionFunc) apply(a *Approver) error { return aof(a) }

// WithPrefixes adds several prefixes used to match capabilities, e.g. x1:webpa:foo:.  Only
// the first prefix found during matching is considered for authorization.  If no prefixes
// are set via this option, the resulting approver will not authorize any requests.
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
// This method returns success (i.e. a nil error) when the first matching capability is found.
//
// This method always returns either bascule.ErrUnauthorized or an *UnauthorizedError, which wraps
// bascule.ErrUnauthorized.
func (a *Approver) Approve(_ context.Context, resource *http.Request, token bascule.Token) error {
	capabilities, ok := bascule.GetCapabilities(token)
	if len(capabilities) == 0 || !ok {
		return ErrMissingCapabilities
	}

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

			if err != nil {
				err = &UnauthorizedError{
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
