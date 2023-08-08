// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"github.com/justinas/alice"
	"go.uber.org/fx"
)

// MetricListenerIn is used for uber fx wiring.
type MetricListenerIn struct {
	fx.In
	M *MetricListener `name:"bascule_metric_listener"`
}

// ChainIn is used for uber fx wiring.
type ChainIn struct {
	fx.In
	SetLogger     alice.Constructor `name:"alice_set_logger"`
	Constructor   alice.Constructor `name:"alice_constructor"`
	Enforcer      alice.Constructor `name:"alice_enforcer"`
	Listener      alice.Constructor `name:"alice_listener"`
	SetLoggerInfo alice.Constructor `name:"alice_set_logger_info"`
}

// Build provides the alice constructors chained together in a set order.
func (c ChainIn) Build() alice.Chain {
	return alice.New(c.SetLogger, c.Constructor, c.Enforcer, c.Listener, c.SetLoggerInfo)
}

// ProvideServerChain builds the alice middleware and then provides them
// together in a single alice chain.
func ProvideServerChain() fx.Option {
	return fx.Options(
		ProvideLogger(),
		ProvideMetricListener(),
		ProvideEnforcer(),
		ProvideConstructor(),
		fx.Provide(
			fx.Annotated{
				Name: "auth_chain",
				Target: func(in ChainIn) alice.Chain {
					return in.Build()
				},
			},
		))
}
