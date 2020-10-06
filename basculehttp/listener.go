/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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

	for _, listener := range listeners {
		l.listeners = append(l.listeners, listener)
	}
	return l.decorate
}
