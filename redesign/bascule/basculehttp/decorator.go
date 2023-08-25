package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule/redesign/bascule"
)

type Decorator[T bascule.Token] struct {
	Next      http.Handler
	Forbidden func(http.ResponseWriter, *http.Request, error)

	Parser        bascule.TokenParser[T]
	Authenticator bascule.Authenticator[T]
	Authorizer    bascule.Authorizer[T]
}

// ServeHTTP executes the security workflow for an HTTP request.
func (h *Decorator[T]) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	token, err := h.Parser.ParseToken(request.Header.Get("Authorization"))
	if err == nil {
		err = h.Authenticator.Authenticate(token)
	}

	if err == nil {
		err = h.Authorizer.Authorize(request, token)
	}

	if err == nil {
		request = request.Clone(
			bascule.WithToken(request.Context(), token),
		)

		h.Next.ServeHTTP(response, request)
	} else {
		h.Forbidden(response, request, err)
	}
}
