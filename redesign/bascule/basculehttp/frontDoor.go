package basculehttp

import (
	"net/http"

	"github.com/xmidt-org/bascule/redesign/bascule"
)

// FrontDoor implements the HTTP-specific workflow for authentication.
// Authorization is handled separately from this workflow.
type FrontDoor struct {
	Next      http.Handler
	Forbidden func(http.ResponseWriter, *http.Request, error)

	Accessor     Accessor
	TokenFactory bascule.TokenFactory
}

func (fd *FrontDoor) accessor() Accessor {
	if fd.Accessor != nil {
		return fd.Accessor
	}

	return defaultAccessor
}

func (fd *FrontDoor) handleInvalidCredentials(response http.ResponseWriter, request *http.Request, err error) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusBadRequest)
	response.Write([]byte(err.Error()))
}

func (fd *FrontDoor) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	raw, err := fd.accessor().GetCredentials(request)
	if err != nil {
		fd.handleInvalidCredentials(response, request, err)
		return
	}

	token, err := fd.TokenFactory.NewToken(raw)
	if err != nil {
		fd.Forbidden(response, request, err)
		return
	}

	request = request.WithContext(
		bascule.WithToken(request.Context(), token),
	)

	fd.Next.ServeHTTP(response, request)
}
