package basculeauth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicAcquirerSuccess(t *testing.T) {
	assert := assert.New(t)
	credentials := "test credentials"
	expctedCredentials := "Basic test credentials"
	acquirer := NewBasicAcquirer(credentials)
	returnedCredentials, err := acquirer.Acquire()
	assert.Nil(err)
	assert.Equal(expctedCredentials, returnedCredentials)
}

func TestBasicAcquirer(t *testing.T) {
	assert := assert.New(t)
	credentials := "Z29waGVyOmhlbGxv"
	plainAcquirer := NewBasicAcquirerPlainText("gopher", "hello")
	acquirer := NewBasicAcquirer(credentials)
	returnedCredentials, err := acquirer.Acquire()
	assert.Nil(err)
	returnedCredentialsPlain, err := plainAcquirer.Acquire()
	assert.Equal(returnedCredentialsPlain, returnedCredentials)
}

func TestBasicAcquirerFailure(t *testing.T) {
	assert := assert.New(t)
	credentials := ""
	acquirer := NewBasicAcquirer(credentials)
	returnedCredentials, err := acquirer.Acquire()
	assert.Equal(errMissingCredentials, err)
	assert.Equal(credentials, returnedCredentials)
}
