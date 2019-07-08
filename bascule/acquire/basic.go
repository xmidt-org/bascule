package acquire

import (
	"encoding/base64"
	"errors"
)

var (
	errMissingCredentials = errors.New("no credentials found")
)

// BasicAcquirer saves a basic auth upon creation and returns it whenever
// Acquire is called.
type BasicAcquirer struct {
	encodedCredentials string
}

func (b *BasicAcquirer) Acquire() (string, error) {
	if b.encodedCredentials == "" {
		return "", errMissingCredentials
	}
	return "Basic " + b.encodedCredentials, nil
}

func NewBasicAcquirer(credentials string) *BasicAcquirer {
	return &BasicAcquirer{credentials}
}

func NewBasicAcquirerPlainText(username, password string) *BasicAcquirer {
	return &BasicAcquirer{base64.StdEncoding.EncodeToString([]byte(username + ":" + password))}
}
