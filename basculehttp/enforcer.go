// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/justinas/alice"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/sallust"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

//go:generate stringer -type=NotFoundBehavior

// NotFoundBehavior is an enum that specifies what to do when the
// Authorization used isn't found in the map of rules.
type NotFoundBehavior int

const (
	Forbid NotFoundBehavior = iota
	Allow
)

// EOption is any function that modifies the enforcer - used to configure
// the enforcer.
type EOption func(*enforcer)

// EOptionsIn is the uber.fx wired struct needed to group together the options
// for the bascule enforcer middleware, which runs checks against the token.
type EOptionsIn struct {
	fx.In
	Options []EOption `group:"bascule_enforcer_options"`
}

type enforcer struct {
	notFoundBehavior NotFoundBehavior
	rules            map[bascule.Authorization]bascule.Validator
	getLogger        func(context.Context) *zap.Logger
	onErrorResponse  OnErrorResponse
}

func (e *enforcer) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		logger := e.getLogger(ctx)
		if logger == nil {
			logger = sallust.Get(ctx)
		}
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			err := errors.New("no authentication found")
			logger.Error(err.Error())
			e.onErrorResponse(MissingAuthentication, err)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		rules, ok := e.rules[auth.Authorization]
		if !ok {
			err := errors.New("no rules found for authorization")
			logger.Error(err.Error(), zap.Any("rules", rules),
				zap.String("authorization", string(auth.Authorization)), zap.Int("behavior", int(e.notFoundBehavior)))
			switch e.notFoundBehavior {
			case Forbid:
				e.onErrorResponse(ChecksNotFound, err)
				response.WriteHeader(http.StatusForbidden)
				return
			case Allow:
				// continue
			default:
				e.onErrorResponse(ChecksNotFound, err)
				response.WriteHeader(http.StatusForbidden)
				return
			}
		} else {
			err := rules.Check(ctx, auth.Token)
			if err != nil {
				logger.Error(err.Error())
				e.onErrorResponse(ChecksFailed, err)
				WriteResponse(response, http.StatusForbidden, err)
				return
			}
		}
		logger.Debug("authentication accepted by enforcer")
		next.ServeHTTP(response, request)
	})
}

// NewListenerDecorator creates an Alice-style decorator function that acts as
// middleware, allowing for Listeners to be called after a token has been
// authenticated.
func NewEnforcer(options ...EOption) func(http.Handler) http.Handler {
	e := &enforcer{
		rules:           make(map[bascule.Authorization]bascule.Validator),
		getLogger:       sallust.Get,
		onErrorResponse: DefaultOnErrorResponse,
	}

	for _, o := range options {
		if o == nil {
			continue
		}
		o(e)
	}

	return e.decorate
}

// WithNotFoundBehavior sets the behavior upon not finding the Authorization
// value in the rules map.
func WithNotFoundBehavior(behavior NotFoundBehavior) EOption {
	return func(e *enforcer) {
		if behavior > 0 {
			e.notFoundBehavior = behavior
		}
	}
}

// WithRules sets the validator to be used for a given Authorization value.
func WithRules(key bascule.Authorization, v bascule.Validator) EOption {
	return func(e *enforcer) {
		if v != nil {
			e.rules[key] = v
		}
	}
}

// WithELogger sets the function to use to get the logger from the context.
// If no logger is set, nothing is logged.
func WithELogger(getLogger func(context.Context) *zap.Logger) EOption {
	return func(e *enforcer) {
		if getLogger != nil {
			e.getLogger = getLogger
		}
	}
}

// WithEErrorResponseFunc sets the function that is called when an error occurs.
func WithEErrorResponseFunc(f OnErrorResponse) EOption {
	return func(e *enforcer) {
		if f != nil {
			e.onErrorResponse = f
		}
	}
}

// ProvideEnforcer is a helper function for wiring up an enforcer with uber fx.
// Any options added with uber fx will be used to create the enforcer.
func ProvideEnforcer() fx.Option {
	return fx.Provide(
		fx.Annotated{
			Name: "alice_enforcer",
			Target: func(in EOptionsIn) alice.Constructor {
				return NewEnforcer(in.Options...)
			},
		},
	)
}
