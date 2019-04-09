package basculehttp

import (
	"context"
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
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
	getLogger        func(context.Context) Logger
}

func (e *enforcer) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		logger := e.getLogger(ctx)
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			logger.Log(bascule.ErrorKey, "no authentication found", "request", request)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		rules, ok := e.rules[auth.Authorization]
		if !ok {
			logger.Log(errorKey, "no rules found for authorization", "request", request)

			switch e.notFoundBehavior {
			case Forbid:
				response.WriteHeader(http.StatusForbidden)
				return
			case Allow:
				// continue
			default:
				response.WriteHeader(http.StatusForbidden)
				return
			}
		} else {
			err := rules.Check(ctx, auth.Token)
			if err != nil {
				errs := []string{err.Error()}
				if es, ok := err.(bascule.Errors); ok {
					for _, e := range es {
						errs = append(errs, e.Error())
					}
				}
				logger.Log(errorKey, errs, "request", request)
				WriteResponse(response, http.StatusUnauthorized, err)
				return
			}
		}
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

func NewEnforcer(options ...EOption) func(http.Handler) http.Handler {
	e := &enforcer{
		rules:     make(map[bascule.Authorization]bascule.Validators),
		getLogger: bascule.GetDefaultLoggerFunc,
	}

	for _, o := range options {
		o(e)
	}

	return e.decorate
}
