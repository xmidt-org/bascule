package acquire

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicAcquirerSuccess(t *testing.T) {
	assert := assert.New(t)
	credentials := "test credentials"
	expctedCredentials := "Basic test credentials"
	acquirer := NewBasicAuthAcquirer(credentials)
	returnedCredentials, err := acquirer.Acquire()
	assert.Nil(err)
	assert.Equal(expctedCredentials, returnedCredentials)
}

func TestBasicAcquirer(t *testing.T) {
	assert := assert.New(t)
	credentials := "Z29waGVyOmhlbGxv"
	plainAcquirer := NewBasicAuthAcquirerPlainText("gopher", "hello")
	acquirer := NewBasicAuthAcquirer(credentials)
	returnedCredentials, err := acquirer.Acquire()
	assert.Nil(err)
	returnedCredentialsPlain, err := plainAcquirer.Acquire()
	assert.Equal(returnedCredentialsPlain, returnedCredentials)
}

func TestBasicAcquirerFailure(t *testing.T) {
	assert := assert.New(t)
	credentials := ""
	acquirer := NewBasicAuthAcquirer(credentials)
	returnedCredentials, err := acquirer.Acquire()
	assert.Equal(errMissingCredentials, err)
	assert.Equal(credentials, returnedCredentials)
}
