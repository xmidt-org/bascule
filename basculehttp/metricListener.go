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
	"time"

	"github.com/SermoDigital/jose/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/bascule"
)

type MetricListener struct {
	expLeeway time.Duration
	nbfLeeway time.Duration
	measures  *AuthValidationMeasures
}

func (m *MetricListener) OnAuthenticated(auth bascule.Authentication) {
	now := time.Now()

	if m.measures == nil {
		return // measure tools are not defined, skip
	}

	if auth.Token == nil {
		return
	}

	m.measures.ValidationOutcome.With(prometheus.Labels{OutcomeLabel: "Accepted"}).Add(1)

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
		m.measures.NBFHistogram.Observe(offsetToNBF)
	}

	//how far did we land from the EXP (in seconds): ie. -1 means 1 sec before, 1 means 1 sec after
	if exp, expPresent := claims.Expiration(); expPresent {
		exp = exp.Add(m.expLeeway)
		offsetToEXP := now.Sub(exp).Seconds()
		m.measures.EXPHistogram.Observe(offsetToEXP)
	}
}

func (m *MetricListener) OnErrorResponse(e ErrorResponseReason, _ error) {
	if m.measures == nil {
		return
	}
	m.measures.ValidationOutcome.With(prometheus.Labels{OutcomeLabel: e.String()}).Add(1)
}

type Option func(m *MetricListener)

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

func NewMetricListener(m *AuthValidationMeasures, options ...Option) *MetricListener {
	listener := MetricListener{
		measures: m,
	}

	for _, o := range options {
		o(&listener)
	}
	return &listener
}
