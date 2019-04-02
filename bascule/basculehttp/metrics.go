package basculehttp

import (
	"net/http"

	"github.com/Comcast/comcast-bascule/bascule"
)

type Listener interface {
	OnAuthenticated(bascule.Authentication)
}

type listenerDecorator struct {
	listener Listener
}

func (m *listenerDecorator) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if m.listener != nil {
			m.listener.OnAuthenticated(auth)
		}
		next.ServeHTTP(response, request)

	})
}

type LOption func(*listenerDecorator)

func WithMeasures(listener Listener) LOption {
	return func(m *listenerDecorator) {
		m.listener = listener
	}
}

func NewListenerDecorator(options ...LOption) func(http.Handler) http.Handler {
	l := &listenerDecorator{}

	for _, o := range options {
		o(l)
	}
	return l.decorate
}
