package basculehttp

import (
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
)

type Monitor interface {
	Monitor(bascule.Authentication)
}

type metrics struct {
	monitor Monitor
}

func (m *metrics) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if m.monitor != nil {
			m.monitor.Monitor(auth)
		}
		next.ServeHTTP(response, request)

	})
}

type MOption func(*metrics)

func WithMeasures(monitor Monitor) MOption {
	return func(m *metrics) {
		m.monitor = monitor
	}
}

func NewMetrics(options ...MOption) func(http.Handler) http.Handler {
	m := &metrics{}

	for _, o := range options {
		o(m)
	}
	return m.decorate
}
