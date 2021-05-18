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
	"time"

	"github.com/SermoDigital/jose/jwt"
	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/bascule"
	"go.uber.org/fx"
)

const (
	defaultServer = "primary"
)

// MetricListener
type MetricListener struct {
	server    string
	expLeeway time.Duration
	nbfLeeway time.Duration
	measures  *AuthValidationMeasures
}

type Option func(m *MetricListener)

type MetricListenerOptionsIn struct {
	fx.In
	Measures AuthValidationMeasures
	Options  []Option `group:"bascule_metric_listener_options"`
}

type LeewayIn struct {
	fx.In
	L bascule.Leeway `name:"jwt_leeway" optional:"true"`
}

func (m *MetricListener) OnAuthenticated(auth bascule.Authentication) {
	now := time.Now()

	if m.measures == nil {
		return // measure tools are not defined, skip
	}

	if auth.Token == nil {
		return
	}

	m.measures.ValidationOutcome.
		With(prometheus.Labels{
			ServerLabel:  m.server,
			OutcomeLabel: "Accepted",
		}).
		Add(1)

	c, ok := auth.Token.Attributes().Get("claims")
	if !ok {
		return // if there aren't any claims, skip
	}
	claims, ok := c.(jwt.Claims)
	if !ok {
		return // if claims aren't what we expect, skip
	}

	//how far did we land from the NBF (in seconds): ie. -1 means 1 sec before, 1 means 1 sec after
	if nbf, nbfPresent := claims.NotBefore(); nbfPresent {
		nbf = nbf.Add(-m.nbfLeeway)
		offsetToNBF := now.Sub(nbf).Seconds()
		m.measures.NBFHistogram.
			With(prometheus.Labels{ServerLabel: m.server}).
			Observe(offsetToNBF)
	}

	//how far did we land from the EXP (in seconds): ie. -1 means 1 sec before, 1 means 1 sec after
	if exp, expPresent := claims.Expiration(); expPresent {
		exp = exp.Add(m.expLeeway)
		offsetToEXP := now.Sub(exp).Seconds()
		m.measures.EXPHistogram.
			With(prometheus.Labels{ServerLabel: m.server}).
			Observe(offsetToEXP)
	}
}

func (m *MetricListener) OnErrorResponse(e ErrorResponseReason, _ error) {
	if m.measures == nil {
		return
	}
	m.measures.ValidationOutcome.
		With(prometheus.Labels{ServerLabel: m.server, OutcomeLabel: e.String()}).
		Add(1)
}

func WithExpLeeway(e time.Duration) Option {
	return func(m *MetricListener) {
		m.expLeeway = e
	}
}

func WithNbfLeeway(n time.Duration) Option {
	return func(m *MetricListener) {
		m.nbfLeeway = n
	}
}

func WithServer(s string) Option {
	return func(m *MetricListener) {
		if s != "" {
			m.server = s
		}
	}
}

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

func ProvideMetricListener() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Group: "bascule_metric_listener_options,flatten",
			Target: func(in LeewayIn) []Option {
				os := []Option{}
				if in.L.EXP > 0 {
					os = append(os, WithExpLeeway(time.Duration(in.L.EXP)))
				}
				if in.L.NBF > 0 {
					os = append(os, WithNbfLeeway(time.Duration(in.L.NBF)))
				}
				return os
			},
		},
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
