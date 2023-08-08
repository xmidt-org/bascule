// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule"
)

// Listener is anything that takes the Authentication information of an
// authenticated Token.
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

// NewListenerDecorator creates an Alice-style decorator function that acts as
// middleware, allowing for Listeners to be called after a token has been
// authenticated.
func NewListenerDecorator(listeners ...Listener) func(http.Handler) http.Handler {
	l := &listenerDecorator{}

	l.listeners = append(l.listeners, listeners...)
	return l.decorate
}
