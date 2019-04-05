package basculehttp

import (
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
)

type enforcer struct {
	rules map[bascule.Authorization]bascule.Validators
}

func (e *enforcer) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		rules, ok := e.rules[auth.Authorization]
		if !ok {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		err := rules.Check(ctx, auth.Token)
		if err != nil {
			errStrings := []string{err.Error()}
			if errs, ok := err.(bascule.MultiError); ok {
				for _, e := range errs.Errors() {
					errStrings = append(errStrings, e.Error())
				}
			}
			errHeaderer := NewErrorHeaderer(err, map[string][]string{
				"authError": errStrings,
			})
			WriteResponse(response, http.StatusUnauthorized, errHeaderer)
			return
		}
		next.ServeHTTP(response, request)
	})
}

type EOption func(*enforcer)

func WithRules(key bascule.Authorization, v bascule.Validators) EOption {
	return func(e *enforcer) {
		e.rules[key] = v
	}
}

func NewEnforcer(options ...EOption) func(http.Handler) http.Handler {
	e := &enforcer{
		rules: make(map[bascule.Authorization]bascule.Validators),
	}

	for _, o := range options {
		o(e)
	}

	return e.decorate
}
