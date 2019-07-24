package acquire

import (
	"encoding/base64"
	"errors"
)

var (
	errMissingCredentials = errors.New("no credentials found")
)

func NewBasicAuthAcquirer(credentials string) Acquirer {
	return &fixedValueAcquirer{
		Auth: "Basic " + credentials}
}

func NewBasicAuthAcquirerPlainText(username, password string) Acquirer {
	return &fixedValueAcquirer{
		Auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))}
}
