/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package basculechecks

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

var (
	ErrGettingPartnerIDs = errWithReason{
		err:    errors.New("couldn't get partner IDs from attributes"),
		reason: UndeterminedPartnerID,
	}
	ErrPartnerIDsNotStringSlice = errWithReason{
		err:    errors.New("expected a string slice"),
		reason: UndeterminedPartnerID,
	}
)

// CapabilitiesChecker is an object that can determine if a request is
// authorized given a bascule.Authentication object.  If it's not authorized, an
//  error is given for logging and metrics.
type CapabilitiesChecker interface {
	CheckAuthentication(auth bascule.Authentication, vals ParsedValues) error
}

// ParsedValues are values determined from the bascule Authentication.
type ParsedValues struct {
	// Endpoint is the string representation of a regular expression that
	// matches the URL for the request.  The main benefit of this string is it
	// most likely won't include values that change from one request to the next
	// (ie, device ID).
	Endpoint string
}

type metricValues struct {
	method    string
	endpoint  string
	partnerID string
	client    string
}

// MetricValidator determines if a request is authorized and then updates a
// metric to show those results.
type MetricValidator struct {
	c         CapabilitiesChecker
	measures  *AuthCapabilityCheckMeasures
	endpoints []*regexp.Regexp
	errorOut  bool
	server    string
}

// Check is a function for authorization middleware.  The function parses the
// information needed for the CapabilitiesChecker, calls it to determine if the
// request is authorized, and maintains the results in a metric.  The function
// can mark the request as unauthorized or only update the metric and allow the
// request, depending on configuration.  This allows for monitoring before being
// more strict with authorization.
func (m MetricValidator) Check(ctx context.Context, _ bascule.Token) error {
	// if we're not supposed to error out, the outcome should be accepted on failure
	failureOutcome := AcceptedOutcome
	if m.errorOut {
		// if we actually error out, the outcome is the request being rejected
		failureOutcome = RejectedOutcome
	}

	auth, ok := bascule.FromContext(ctx)
	if !ok {
		m.measures.CapabilityCheckOutcome.With(prometheus.Labels{
			ServerLabel:    m.server,
			OutcomeLabel:   failureOutcome,
			ReasonLabel:    TokenMissing,
			ClientIDLabel:  "",
			PartnerIDLabel: "",
			EndpointLabel:  "",
			MethodLabel:    "",
		}).Add(1)
		if m.errorOut {
			return ErrNoAuth
		}
		return nil
	}

	l, err := m.prepMetrics(auth)
	labels := prometheus.Labels{
		ServerLabel:    m.server,
		ClientIDLabel:  l.client,
		PartnerIDLabel: l.partnerID,
		EndpointLabel:  l.endpoint,
		MethodLabel:    l.method,
		OutcomeLabel:   AcceptedOutcome,
		ReasonLabel:    "",
	}
	if err != nil {
		labels[OutcomeLabel] = failureOutcome
		labels[ReasonLabel] = UnknownReason
		var r Reasoner
		if errors.As(err, &r) {
			labels[ReasonLabel] = r.Reason()
		}
		m.measures.CapabilityCheckOutcome.With(labels).Add(1)
		if m.errorOut {
			return err
		}
		return nil
	}

	v := ParsedValues{
		Endpoint: l.endpoint,
	}

	err = m.c.CheckAuthentication(auth, v)
	if err != nil {
		labels[OutcomeLabel] = failureOutcome
		labels[ReasonLabel] = UnknownReason
		var r Reasoner
		if errors.As(err, &r) {
			labels[ReasonLabel] = r.Reason()
		}
		m.measures.CapabilityCheckOutcome.With(labels).Add(1)
		if m.errorOut {
			return fmt.Errorf("endpoint auth for %v on %v failed: %v",
				auth.Request.Method, auth.Request.URL.EscapedPath(), err)
		}
		return nil
	}

	m.measures.CapabilityCheckOutcome.With(labels).Add(1)
	return nil
}

// prepMetrics gathers the information needed for metric label information.  It
// gathers the client ID, partnerID, and endpoint (bucketed) for more information
// on the metric when a request is unauthorized.
func (m MetricValidator) prepMetrics(auth bascule.Authentication) (metricValues, error) {
	v := metricValues{}
	if auth.Token == nil {
		return v, ErrNoToken
	}
	v.client = auth.Token.Principal()
	if len(auth.Request.Method) == 0 {
		return v, ErrNoMethod
	}
	v.method = auth.Request.Method
	if auth.Token.Attributes() == nil {
		return v, ErrNilAttributes
	}

	partnerVal, ok := bascule.GetNestedAttribute(auth.Token.Attributes(), PartnerKeys()...)
	if !ok {
		err := fmt.Errorf("%w using keys %v", ErrGettingPartnerIDs, PartnerKeys())
		return v, err
	}
	partnerIDs, err := cast.ToStringSliceE(partnerVal)
	if err != nil {
		err = fmt.Errorf("%w for partner IDs \"%v\": %v",
			ErrPartnerIDsNotStringSlice, partnerVal, err)
		return v, err
	}
	v.partnerID = DeterminePartnerMetric(partnerIDs)

	if auth.Request.URL == nil {
		return v, ErrNoURL
	}
	escapedURL := auth.Request.URL.EscapedPath()
	v.endpoint = determineEndpointMetric(m.endpoints, escapedURL)
	return v, nil
}

func NewMetricValidator(checker CapabilitiesChecker, measures *AuthCapabilityCheckMeasures, options ...MetricOption) (*MetricValidator, error) {
	m := MetricValidator{
		c:        checker,
		measures: measures,
		errorOut: true,
	}

	for _, o := range options {
		o(&m)
	}
	return &m, nil
}

func ProvideMetricValidator(server string) fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name:   fmt.Sprintf("%s_bascule_capability_measures", server),
			Target: NewMetricValidator,
		},
	)
}
