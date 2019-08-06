package acquire

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestAddAuth(t *testing.T) {

	t.Run("RequestIsNil", func(t *testing.T) {
		assert := assert.New(t)
		assert.NotNil(AddAuth(nil, &DefaultAcquirer{}))
	})

	t.Run("AcquirerIsNil", func(t *testing.T) {
		assert := assert.New(t)
		assert.NotNil(AddAuth(httptest.NewRequest(http.MethodGet, "/", nil), nil))
	})

	t.Run("AcquirerFails", func(t *testing.T) {
		assert := assert.New(t)
		assert.NotNil(AddAuth(httptest.NewRequest(http.MethodGet, "/", nil), &failingAcquirer{}))
	})

	t.Run("HappyPath", func(t *testing.T) {
		assert := assert.New(t)
		acquirer, err := NewFixedAuthAcquirer("Basic abc==")
		assert.Nil(err)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		assert.Nil(AddAuth(r, acquirer))
		assert.Equal("Basic abc==", r.Header.Get("Authorization"))
	})
}

func TestFixedAuthAcquirer(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		assert := assert.New(t)

		acquirer, err := NewFixedAuthAcquirer("Basic xyz==")
		assert.NotNil(acquirer)
		assert.Nil(err)

		authValue, _ := acquirer.Acquire()
		assert.Equal("Basic xyz==", authValue)
	})

	t.Run("EmptyCredentials", func(t *testing.T) {
		assert := assert.New(t)

		acquirer, err := NewFixedAuthAcquirer("")
		assert.Equal(ErrEmptyCredentials, err)
		assert.Nil(acquirer)
	})
}

func TestDefaultAcquirer(t *testing.T) {
	assert := assert.New(t)
	acquirer := &DefaultAcquirer{}
	authValue, err := acquirer.Acquire()
	assert.Empty(authValue)
	assert.Empty(err)
}

type failingAcquirer struct{}

func (f *failingAcquirer) Acquire() (string, error) {
	return "", errors.New("always fails")
}
