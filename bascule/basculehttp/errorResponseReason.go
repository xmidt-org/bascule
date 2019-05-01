package basculehttp

//go:generate stringer -type=ErrorResponseReason
type ErrorResponseReason int

// Behavior on not found
const (
	MissingHeader ErrorResponseReason = iota
	InvalidHeader
	KeyNotSupported
	ParseFailed
	MissingAuthentication
	ChecksNotFound
	ChecksFailed
)

type OnErrorResponse func(ErrorResponseReason, error)

// default function does nothing
func DefaultOnErrorResponse(_ ErrorResponseReason, _ error) {
	return
}
