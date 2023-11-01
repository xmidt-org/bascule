// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/xmidt-org/bascule"
)

var (
	ErrNilDefaultChecker = errors.New("default checker cannot be nil")
	ErrEmptyEndpoint     = errWithReason{
		err:    errors.New("endpoint provided is empty"),
		reason: EmptyParsedURL,
	}
	errRegexCompileFail = errors.New("failed to compile regexp")
)

// CapabilitiesMapConfig includes the values needed to set up a map capability
// checker.  The checker will verify that one of the capabilities in a provided
// JWT match the string meant for that endpoint exactly.  A CapabilitiesMap set
// up with this will use the default KeyPath.
type CapabilitiesMapConfig struct {
	Endpoints map[string]string `json:"endpoints" yaml:"endpoints"`
	Default   string            `json:"default" yaml:"default"`
}

// CapabilitiesMap runs a capability check based on the value of the parsedURL,
// which is the key to the CapabilitiesMap's map.  The parsedURL is expected to
// be some regex values, allowing for bucketing of urls that contain some kind
// of ID or otherwise variable portion of a URL.
type CapabilitiesMap struct {
	Checkers       map[string]EndpointChecker
	DefaultChecker EndpointChecker
	KeyPath        []string
}

// CheckAuthentication uses the parsed endpoint value to determine which EndpointChecker to
// run against the capabilities in the auth provided.  If there is no
// EndpointChecker for the endpoint, the default is used.  As long as one
// capability is found to be authorized by the EndpointChecker, no error is
// returned.
func (c CapabilitiesMap) CheckAuthentication(auth bascule.Authentication, vs ParsedValues) error {
	if auth.Token == nil {
		return ErrNoToken
	}

	if auth.Request.URL == nil {
		return ErrNoURL
	}

	if vs.Endpoint == "" {
		return ErrEmptyEndpoint
	}

	capabilities, err := getCapabilities(auth.Token.Attributes(), c.KeyPath)
	if err != nil {
		return err
	}

	// determine which EndpointChecker to use.
	checker, ok := c.Checkers[vs.Endpoint]
	if !ok || checker == nil {
		checker = c.DefaultChecker
	}
	reqURL := auth.Request.URL.EscapedPath()
	method := auth.Request.Method

	// if the checker is nil, we treat it like a checker that always returns
	// false.
	if checker == nil {
		// ErrNoValidCapabilityFound is a Reasoner.
		return fmt.Errorf("%w in [%v] with nil endpoint checker",
			ErrNoValidCapabilityFound, capabilities)
	}

	// if one of the capabilities is good, then the request is authorized
	// for this endpoint.
	for _, capability := range capabilities {
		if checker.Authorized(capability, reqURL, method) {
			return nil
		}
	}

	return fmt.Errorf("%w in [%v] with %v endpoint checker",
		ErrNoValidCapabilityFound, capabilities, checker.Name())
}

// NewCapabilitiesMap parses the CapabilitiesMapConfig provided into a
// CapabilitiesMap.  The same regular expression provided for the map are also
// needed for labels for a MetricValidator, so an option to be used for that is
// also created.
func NewCapabilitiesMap(config CapabilitiesMapConfig) (CapabilitiesCheckerOut, error) {
	// if we don't get a capability value, a nil default checker means always
	// returning false.
	var defaultChecker EndpointChecker
	if config.Default != "" {
		defaultChecker = ConstEndpointCheck(config.Default)
	}

	i := 0
	rs := make([]*regexp.Regexp, len(config.Endpoints))
	endpointMap := map[string]EndpointChecker{}
	for r, checkVal := range config.Endpoints {
		regex, err := regexp.Compile(r)
		if err != nil {
			return CapabilitiesCheckerOut{}, fmt.Errorf("%w [%v]: %v", errRegexCompileFail, r, err)
		}
		// because rs is the length of config.Endpoints, i never overflows.
		rs[i] = regex
		i++
		endpointMap[r] = ConstEndpointCheck(checkVal)
	}

	cc := CapabilitiesMap{
		Checkers:       endpointMap,
		DefaultChecker: defaultChecker,
	}

	return CapabilitiesCheckerOut{
		Checker: cc,
		Options: []MetricOption{WithEndpoints(rs)},
	}, nil
}
