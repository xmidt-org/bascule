package basculehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Comcast/comcast-bascule/bascule"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	next = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
)

func TestListenerDecorator(t *testing.T) {
	assert := assert.New(t)
	mockListener := new(mockListener)
	mockListener.On("OnAuthenticated", mock.Anything).Once()
	f := NewListenerDecorator(mockListener)
	handler := f(next)

	writer := httptest.NewRecorder()
	req := httptest.NewRequest("get", "/", nil)
	handler.ServeHTTP(writer, req)
	assert.Equal(http.StatusForbidden, writer.Code)

	ctx := bascule.WithAuthentication(context.Background(), bascule.Authentication{
		Authorization: "jwt",
		Token:         bascule.NewToken("", "", bascule.Attributes{}),
		Request: bascule.Request{
			URL:    "/",
			Method: "get",
		},
	})
	req = req.WithContext(ctx)
	writer = httptest.NewRecorder()
	handler.ServeHTTP(writer, req)
	assert.Equal(http.StatusOK, writer.Code)

}
