package basculehttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/goph/emperror"

	"github.com/xmidt-org/bascule/bascule"
	"github.com/go-kit/kit/log/level"
)

//go:generate stringer -type=NotFoundBehavior

type NotFoundBehavior int

// Behavior on not found
const (
	Forbid NotFoundBehavior = iota
	Allow
)

type enforcer struct {
	notFoundBehavior NotFoundBehavior
	rules            map[bascule.Authorization]bascule.Validators
	getLogger        func(context.Context) bascule.Logger
	onErrorResponse  OnErrorResponse
}

func (e *enforcer) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		logger := e.getLogger(ctx)
		if logger == nil {
			logger = bascule.GetDefaultLoggerFunc(ctx)
		}
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			err := errors.New("no authentication found")
			logger.Log(level.Key(), level.ErrorValue(), bascule.ErrorKey, err.Error())
			e.onErrorResponse(MissingAuthentication, err)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		rules, ok := e.rules[auth.Authorization]
		if !ok {
			err := errors.New("no rules found for authorization")
			logger.Log(level.Key(), level.ErrorValue(),
				bascule.ErrorKey, err.Error(), "rules", rules,
				"authorization", auth.Authorization, "behavior", e.notFoundBehavior)
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
				logger.Log(append(emperror.Context(err), level.Key(), level.ErrorValue(), bascule.ErrorKey, err)...)
				e.onErrorResponse(ChecksFailed, err)
				WriteResponse(response, http.StatusForbidden, err)
				return
			}
		}
		logger.Log(level.Key(), level.DebugValue(), "msg", "authentication accepted by enforcer")
		next.ServeHTTP(response, request)
	})
}

type EOption func(*enforcer)

func WithNotFoundBehavior(behavior NotFoundBehavior) EOption {
	return func(e *enforcer) {
		e.notFoundBehavior = behavior
	}
}

func WithRules(key bascule.Authorization, v bascule.Validators) EOption {
	return func(e *enforcer) {
		e.rules[key] = v
	}
}

func WithELogger(getLogger func(context.Context) bascule.Logger) EOption {
	return func(e *enforcer) {
		e.getLogger = getLogger
	}
}

func WithEErrorResponseFunc(f OnErrorResponse) EOption {
	return func(e *enforcer) {
		e.onErrorResponse = f
	}
}

func NewEnforcer(options ...EOption) func(http.Handler) http.Handler {
	e := &enforcer{
		rules:           make(map[bascule.Authorization]bascule.Validators),
		getLogger:       bascule.GetDefaultLoggerFunc,
		onErrorResponse: DefaultOnErrorResponse,
	}

	for _, o := range options {
		o(e)
	}

	return e.decorate
}
