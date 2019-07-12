package bascule

import (
	"context"
)

// Authorization represents the authorization mechanism performed on the token,
// e.g. "Basic", "Bearer", etc for HTTP security environments.
type Authorization string

// Authentication represents the output of a security pipeline.
type Authentication struct {
	Authorization Authorization
	Token         Token
	Request       Request
}

// Request holds request information that may be useful for validating the
// token.
type Request struct {
	URL    string
	Method string
}

type authenticationKey struct{}

// WithAuthentication adds the auth given to the context given, provided a way
// for other users of the context to get the authentication.
func WithAuthentication(ctx context.Context, auth Authentication) context.Context {
	return context.WithValue(ctx, authenticationKey{}, auth)
}

// FromContext gets the Authentication from the context provided.
func FromContext(ctx context.Context) (Authentication, bool) {
	auth, ok := ctx.Value(authenticationKey{}).(Authentication)
	return auth, ok
}
