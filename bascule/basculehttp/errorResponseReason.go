package basculehttp

//go:generate stringer -type=ErrorResponseReason

// ErrorResponseReason is an enum that specifies the reason parsing/validating
// a token failed.  Its primary use is for metrics and logging.
type ErrorResponseReason int

const (
	MissingHeader ErrorResponseReason = iota
	InvalidHeader
	KeyNotSupported
	ParseFailed
	MissingAuthentication
	ChecksNotFound
	ChecksFailed
)

// OnErrorResponse is a function that takes the error response reason and the
// error and can do something with it.  This is useful for adding additional
// metrics or logs.
type OnErrorResponse func(ErrorResponseReason, error)

// default function does nothing
func DefaultOnErrorResponse(_ ErrorResponseReason, _ error) {
	return
}
