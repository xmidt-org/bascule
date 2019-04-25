package basculehttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorHeaderer(t *testing.T) {
	assert := assert.New(t)
	expectedErr := "test error"
	headers := map[string][]string{"test key": []string{"a", "b", "c", "d"}}
	eh := NewErrorHeaderer(errors.New(expectedErr), headers)
	e, ok := eh.(headerer)
	assert.True(ok)
	err := eh.Error()
	assert.Equal(expectedErr, err)
	h := e.Headers()
	assert.Equal(http.Header(headers), h)
}

type coder int

func (b coder) StatusCode() int {
	return int(b)
}

func TestWriteResponse(t *testing.T) {
	assert := assert.New(t)
	recorder := httptest.NewRecorder()
	err := errors.New("test error")
	headers := map[string][]string{"test key": []string{"a", "b", "c", "d"}}
	WriteResponse(recorder, http.StatusOK, NewErrorHeaderer(err, headers))
	assert.Equal(http.StatusOK, recorder.Code)
	assert.Equal(http.Header(headers), recorder.Header())
	recorder = httptest.NewRecorder()
	c := coder(http.StatusForbidden)
	WriteResponse(recorder, http.StatusBadRequest, c)
	assert.Equal(http.StatusForbidden, recorder.Code)
	assert.Equal(http.Header{}, recorder.Header())
}
