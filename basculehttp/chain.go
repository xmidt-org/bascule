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
	SetLogger   alice.Constructor `name:"alice_set_logger"`
	Constructor alice.Constructor `name:"alice_constructor"`
	Enforcer    alice.Constructor `name:"alice_enforcer"`
	Listener    alice.Constructor `name:"alice_listener"`
}

// Build provides the alice constructors chained together in a set order.
func (c ChainIn) Build() alice.Chain {
	return alice.New(c.SetLogger, c.Constructor, c.Enforcer, c.Listener)
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
