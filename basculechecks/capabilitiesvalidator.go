// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
)

var (
	ErrNoAuth = errors.New("couldn't get request info: authorization not found")
	ErrNoVals = errWithReason{
		err:    errors.New("expected at least one value"),
		reason: EmptyCapabilitiesList,
	}
	ErrNoToken = errWithReason{
		err:    errors.New("no token found in Auth"),
		reason: MissingValues,
	}
	ErrNoValidCapabilityFound = errWithReason{
		err:    errors.New("no valid capability for endpoint"),
		reason: NoCapabilitiesMatch,
	}
	ErrNilAttributes = errWithReason{
		err:    errors.New("nil attributes interface"),
		reason: MissingValues,
	}
	ErrNoMethod = errWithReason{
		err:    errors.New("no method found in Auth"),
		reason: MissingValues,
	}
	ErrNoURL = errWithReason{
		err:    errors.New("invalid URL found in Auth"),
		reason: MissingValues,
	}
	ErrGettingCapabilities = errWithReason{
		err:    errors.New("couldn't get capabilities from attributes"),
		reason: UndeterminedCapabilities,
	}
	ErrCapabilityNotStringSlice = errWithReason{
		err:    errors.New("expected a string slice"),
		reason: UndeterminedCapabilities,
	}
)

// EndpointChecker is an object that can determine if a value provides
// authorization to the endpoint.
type EndpointChecker interface {
	Authorized(value string, reqURL string, method string) bool
	Name() string
}

// CapabilitiesValidatorConfig is input that can be used to build a
// CapabilitiesValidator and some metric options for a MetricValidator. A
// CapabilitiesValidator set up with this will use the default KeyPath and an
// EndpointRegexCheck.
type CapabilitiesValidatorConfig struct {
	Type            string
	Prefix          string
	AcceptAllMethod string
	EndpointBuckets []string
}

// CapabilitiesValidator checks the capabilities provided in a
// bascule.Authentication object to determine if a request is authorized.  It
// can also provide a function to be used in authorization middleware that
// pulls the Authentication object from a context before checking it.
type CapabilitiesValidator struct {
	Checker  EndpointChecker
	KeyPath  []string
	ErrorOut bool
}

// Check determines whether or not a client is authorized to make a request to
// an endpoint.  It uses the bascule.Authentication from the context to get the
// information needed by the EndpointChecker to determine authorization.
func (c CapabilitiesValidator) Check(ctx context.Context, _ bascule.Token) error {
	auth, ok := bascule.FromContext(ctx)
	if !ok {
		if c.ErrorOut {
			return ErrNoAuth
		}
		return nil
	}

	err := c.CheckAuthentication(auth, ParsedValues{})
	if err != nil && c.ErrorOut {
		return fmt.Errorf("endpoint auth for %v on %v failed: %v",
			auth.Request.Method, auth.Request.URL.EscapedPath(), err)
	}

	return nil
}

// CheckAuthentication takes the needed values out of the given Authentication object in
// order to determine if a request is authorized.  It determines this through
// iterating through each capability and calling the EndpointChecker.  If no
// capability authorizes the client for the given endpoint and method, it is
// unauthorized.
func (c CapabilitiesValidator) CheckAuthentication(auth bascule.Authentication, _ ParsedValues) error {
	if auth.Token == nil {
		return ErrNoToken
	}
	if len(auth.Request.Method) == 0 {
		return ErrNoMethod
	}
	vals, err := getCapabilities(auth.Token.Attributes(), c.KeyPath)
	if err != nil {
		return err
	}

	if auth.Request.URL == nil {
		return ErrNoURL
	}
	reqURL := auth.Request.URL.EscapedPath()
	method := auth.Request.Method
	return c.checkCapabilities(vals, reqURL, method)
}

// checkCapabilities uses a EndpointChecker to check if each capability
// provided is authorized.  If an authorized capability is found, no error is
// returned.
func (c CapabilitiesValidator) checkCapabilities(capabilities []string, reqURL string, method string) error {
	for _, val := range capabilities {
		if c.Checker.Authorized(val, reqURL, method) {
			return nil
		}
	}
	return fmt.Errorf("%w in [%v] with %v endpoint checker",
		ErrNoValidCapabilityFound, capabilities, c.Checker.Name())

}

// getCapabilities runs some error checks while getting the list of
// capabilities from the attributes.
func getCapabilities(attributes bascule.Attributes, keyPath []string) ([]string, error) {
	if attributes == nil {
		return []string{}, ErrNilAttributes
	}

	if len(keyPath) == 0 {
		keyPath = CapabilityKeys()
	}

	val, ok := bascule.GetNestedAttribute(attributes, keyPath...)
	if !ok {
		return []string{}, fmt.Errorf("%w using key path %v",
			ErrGettingCapabilities, keyPath)
	}

	vals, err := cast.ToStringSliceE(val)
	if err != nil {
		return []string{}, fmt.Errorf("%w for capabilities \"%v\": %v",
			ErrCapabilityNotStringSlice, val, err)
	}

	if len(vals) == 0 {
		return []string{}, ErrNoVals
	}

	return vals, nil

}

// NewCapabilitiesValidator uses the provided config to create an
// RegexEndpointCheck and wrap it in a CapabilitiesValidator.  Metric Options
// are also created for a Metric Validator by parsing the type to determine if
// the metric validator should only monitor and compiling endpoints into Regexps.
func NewCapabilitiesValidator(config CapabilitiesValidatorConfig) (CapabilitiesCheckerOut, error) {
	var out CapabilitiesCheckerOut
	if config.Type != "enforce" && config.Type != "monitor" {
		// unsupported capability check type. CapabilityCheck disabled.
		return out, nil
	}
	c, err := NewRegexEndpointCheck(config.Prefix, config.AcceptAllMethod)
	if err != nil {
		return out, fmt.Errorf("error initializing endpointRegexCheck: %w", err)
	}

	endpoints := make([]*regexp.Regexp, 0, len(config.EndpointBuckets))
	for _, e := range config.EndpointBuckets {
		r, err := regexp.Compile(e)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, r)
	}

	os := []MetricOption{WithEndpoints(endpoints)}
	if config.Type == "monitor" {
		os = append(os, MonitorOnly())
	}

	out = CapabilitiesCheckerOut{
		Checker: CapabilitiesValidator{Checker: c},
		Options: os,
	}
	return out, nil
}
