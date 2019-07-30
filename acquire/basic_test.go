package acquire

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicAuthAcquirerSuccess(t *testing.T) {
	assert := assert.New(t)
	acquirer := NewBasicAuthAcquirer("test credentials")

	actual, err := acquirer.Acquire()

	assert.Nil(err)
	assert.Equal("Basic test credentials", actual)
}

func TestBasicAuthAcquirersEquality(t *testing.T) {
	assert := assert.New(t)

	plainTextAcquirer := NewBasicAuthAcquirerPlainText("gopher", "hello")
	acquirer := NewBasicAuthAcquirer("Z29waGVyOmhlbGxv")

	acquirerAuthorization, err := acquirer.Acquire()
	assert.Nil(err)

	plainTextAcquirerAuthorization, err := plainTextAcquirer.Acquire()
	assert.Nil(err)

	assert.Equal(acquirerAuthorization, plainTextAcquirerAuthorization)
}

func TestBasicAuthAcquirerFailure(t *testing.T) {
	assert := assert.New(t)
	acquirer := NewBasicAuthAcquirer("")

	authorization, err := acquirer.Acquire()

	assert.Equal(ErrMissingAuthValue, err)
	assert.Empty(authorization)
}
