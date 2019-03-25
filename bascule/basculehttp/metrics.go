package basculehttp

import (
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
)

// some metrics to be added: token type, partner id used, capabilities, source of request (principal?)

type metrics struct {
	measures bascule.Measures
}

func (m *metrics) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if m.measures.TokenCount != nil {
			m.measures.TokenCount.With(bascule.TokenTypeLabel, auth.Token.Type()).Add(1.0)
		}
		next.ServeHTTP(response, request)

	})
}

type MOption func(*metrics)

func WithMeasures(measures bascule.Measures) MOption {
	return func(m *metrics) {
		m.measures = measures
	}
}

func NewMetrics(options ...MOption) func(http.Handler) http.Handler {
	m := &metrics{}

	for _, o := range options {
		o(m)
	}
	return m.decorate
}
