package basculehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/bascule"
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

	u, err := url.ParseRequestURI("/")
	assert.Nil(err)

	ctx := bascule.WithAuthentication(context.Background(), bascule.Authentication{
		Authorization: "jwt",
		Token:         bascule.NewToken("", "", bascule.Attributes{}),
		Request: bascule.Request{
			URL:    u,
			Method: "get",
		},
	})
	req = req.WithContext(ctx)
	writer = httptest.NewRecorder()
	handler.ServeHTTP(writer, req)
	assert.Equal(http.StatusOK, writer.Code)

}
