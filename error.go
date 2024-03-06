// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// ErrorType is an enumeration type for various types of security errors.
// This type can be used to determine more detail about the context of an error.
type ErrorType int

const (
	// ErrorTypeUnknown indicates an error that didn't specify an ErrorType,
	// possibly because the error didn't implement the Error interface in this package.
	ErrorTypeUnknown ErrorType = iota

	// ErrorTypeMissingCredentials indicates that no credentials could be found.
	// For example, this is the type used when no credentials are present in an HTTP request.
	ErrorTypeMissingCredentials

	// ErrorTypeBadCredentials indcates that credentials exist, but they were badly formatted.
	// In other words, bascule could not parse the credentials.
	ErrorTypeBadCredentials

	// ErrorTypeInvalidCredentials indicates that credentials exist and are properly formatted,
	// but they failed validation.  Typically, this is due to failed authentication.  It can also
	// mean that a token's fields are invalid, such as the exp field of a JWT.
	ErrorTypeInvalidCredentials

	// ErrorTypeUnauthorized indicates that a token did not have sufficient privileges to
	// perform an operation.
	ErrorTypeUnauthorized
)

// Error is an optional interface that errors may implement to expose security
// metadata about the error.
type Error interface {
	// Type is the ErrorType describing this error.
	Type() ErrorType
}

// GetErrorType examines err to determine its associated metadata type.  If err
// does not implement Error, this function returns ErrorTypeUnknown.
func GetErrorType(err error) ErrorType {
	if e, ok := err.(Error); ok {
		return e.Type()
	}

	return ErrorTypeUnknown
}
