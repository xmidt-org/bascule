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

package basculehttp

import (
	"errors"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

const (
	defaultServer = "primary"
)

// MetricListener keeps track of request authentication and authorization using
// metrics. A counter is updated on success and failure to reflect the outcome
// and reason for failure, if applicable. MetricListener implements the Listener
// and has an OnErrorResponse function in order for the metrics to be updated at
// the correct time.
type MetricListener struct {
	server   string
	measures *AuthValidationMeasures
}

// Option is how the MetricListener is configured.
type Option func(m *MetricListener)

// MetricListenerOptionsIn is an uber fx wired struct that can be used to build
// a MetricListener.
type MetricListenerOptionsIn struct {
	fx.In
	Measures AuthValidationMeasures
	Options  []Option `group:"bascule_metric_listener_options"`
}

// OnAuthenticated is called after a request passes through the constructor and
// enforcer successfully.  It updates various metrics related to the accepted
// request.
func (m *MetricListener) OnAuthenticated(auth bascule.Authentication) {
	outcome := AcceptedOutcome
	// this is weird and we should take note of it.
	if auth.Token == nil {
		outcome = EmptyOutcome
	}
	m.measures.ValidationOutcome.
		With(prometheus.Labels{
			ServerLabel:  m.server,
			OutcomeLabel: outcome,
		}).
		Add(1)
}

// OnErrorResponse is called if the constructor or enforcer have a problem with
// authenticating/authorizing the request.  The ErrorResponseReason is used as
// the outcome label value in a metric.
func (m *MetricListener) OnErrorResponse(e ErrorResponseReason, _ error) {
	m.measures.ValidationOutcome.
		With(prometheus.Labels{ServerLabel: m.server, OutcomeLabel: e.String()}).
		Add(1)
}

// WithServer provides the server label value to be used by all MetricListener
// metrics.
func WithServer(s string) Option {
	return func(m *MetricListener) {
		if s != "" {
			m.server = s
		}
	}
}

// NewMetricListener creates a new MetricListener that uses the measures
// provided and is configured with the given options. The measures cannot be
// nil.
func NewMetricListener(m *AuthValidationMeasures, options ...Option) (*MetricListener, error) {
	if m == nil {
		return nil, errors.New("measures cannot be nil")
	}

	listener := MetricListener{
		server:   defaultServer,
		measures: m,
	}

	for _, o := range options {
		o(&listener)
	}
	return &listener, nil
}

// ProvideMetricListener provides the metric listener as well as the options
// needed for adding it into various middleware.
func ProvideMetricListener() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name: "bascule_metric_listener",
			Target: func(in MetricListenerOptionsIn) (*MetricListener, error) {
				return NewMetricListener(&in.Measures, in.Options...)
			},
		},
		fx.Annotated{
			Name: "alice_listener",
			Target: func(in MetricListenerIn) alice.Constructor {
				return NewListenerDecorator(in.M)
			},
		},
		fx.Annotated{
			Group: "bascule_constructor_options",
			Target: func(in MetricListenerIn) COption {
				return WithCErrorResponseFunc(in.M.OnErrorResponse)
			},
		},
		fx.Annotated{
			Group: "bascule_enforcer_options",
			Target: func(in MetricListenerIn) EOption {
				return WithEErrorResponseFunc(in.M.OnErrorResponse)
			},
		},
	)
}
