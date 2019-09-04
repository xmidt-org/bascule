package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule/bascule"
)

type Listener interface {
	OnAuthenticated(bascule.Authentication)
}

type listenerDecorator struct {
	listeners []Listener
}

func (l *listenerDecorator) decorate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		for _, listener := range l.listeners {
			listener.OnAuthenticated(auth)
		}
		next.ServeHTTP(response, request)

	})
}

func NewListenerDecorator(listeners ...Listener) func(http.Handler) http.Handler {
	l := &listenerDecorator{}

	for _, listener := range listeners {
		l.listeners = append(l.listeners, listener)
	}
	return l.decorate
}
