// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"fmt"
	"regexp"
	"strings"
)

// AlwaysEndpointCheck is a EndpointChecker that always returns either true or false.
type AlwaysEndpointCheck bool

// Authorized returns the saved boolean value, rather than checking the
// parameters given.
func (a AlwaysEndpointCheck) Authorized(_, _, _ string) bool {
	return bool(a)
}

// Name returns the endpoint check's name.
func (a AlwaysEndpointCheck) Name() string {
	if a {
		return "always true"
	}
	return "always false"
}

// ConstEndpointCheck is a basic EndpointChecker that determines a capability is
// authorized if it matches the ConstCheck's string.
type ConstEndpointCheck string

// Authorized validates the capability provided against the stored string.
func (c ConstEndpointCheck) Authorized(capability, _, _ string) bool {
	return string(c) == capability
}

// Name returns the endpoint check's name.
func (c ConstEndpointCheck) Name() string {
	return "const"
}

// RegexEndpointCheck uses a regular expression to validate an endpoint and
// method provided in a capability against the endpoint hit and method used for
// the request.
type RegexEndpointCheck struct {
	prefixToMatch   *regexp.Regexp
	acceptAllMethod string
}

// NewRegexEndpointCheck creates an object that implements the EndpointChecker
// interface.  It takes a prefix that is expected at the beginning of a
// capability and a string that, if provided in the capability, authorizes all
// methods for that endpoint.  After the prefix, the RegexEndpointCheck expects
// there to be an endpoint regular expression and an http method - separated by
// a colon. The expected format of a capability is: <prefix><endpoint
// regex>:<method>
// Note, the endpoint url path and the capabilities substring (used for authorization)
// will be normalized to have a leading `/` if missing.
func NewRegexEndpointCheck(prefix string, acceptAllMethod string) (RegexEndpointCheck, error) {
	matchPrefix, err := regexp.Compile("^" + prefix + "(.+):(.+?)$")
	if err != nil {
		return RegexEndpointCheck{}, fmt.Errorf("failed to compile prefix [%v]: %w", prefix, err)
	}

	r := RegexEndpointCheck{
		prefixToMatch:   matchPrefix,
		acceptAllMethod: acceptAllMethod,
	}
	return r, nil
}

// Authorized checks the capability against the endpoint hit and method used. If
// the capability has the correct prefix and is meant to be used with the method
// provided to access the endpoint provided, it is authorized.
func (r RegexEndpointCheck) Authorized(capability string, urlToMatch string, methodToMatch string) bool {
	matches := r.prefixToMatch.FindStringSubmatch(capability)

	if matches == nil || len(matches) < 2 {
		return false
	}

	method := matches[2]
	if method != r.acceptAllMethod && method != strings.ToLower(methodToMatch) {
		return false
	}

	re, err := regexp.Compile(urlPathNormalization(matches[1])) //url regex that capability grants access to
	if err != nil {
		return false
	}

	matchIdxs := re.FindStringIndex(urlPathNormalization(urlToMatch))
	if matchIdxs == nil || matchIdxs[0] != 0 {
		return false
	}

	return true
}

// Name returns the endpoint check's name.
func (e RegexEndpointCheck) Name() string {
	return "regex"
}

// urlPathNormalization returns an url path with a leading `/` if missing,
// otherwise the same unmodified url path is returned.
func urlPathNormalization(url string) string {
	if url[0] == '/' {
		return url
	}

	return "/" + url
}
