package acquire

import (
	"encoding/base64"
)

//NewBasicAuthAcquirer provides an Acquirer compatible with encoded basic auth credentials
func NewBasicAuthAcquirer(credentials string) Acquirer {
	return &fixedValueAcquirer{
		AuthValue: credentials,
		AuthType:  "Basic"}
}

//NewBasicAuthAcquirerPlainText provides an Acquirer compatible with plain text basic auth credentials
func NewBasicAuthAcquirerPlainText(username, password string) Acquirer {
	return &fixedValueAcquirer{
		AuthValue: base64.StdEncoding.EncodeToString([]byte(username + ":" + password)),
		AuthType:  "Basic"}
}
