package bascule

import "context"

// Authorization represents the authorization mechanism performed on the token,
// e.g. "Basic", "Bearer", etc for HTTP security environments.
type Authorization string

// Authentication represents the output of a security pipeline.
type Authentication struct {
	Authorization Authorization
	Token         Token
}

type authenticationKey struct{}

func WithAuthentication(ctx context.Context, auth Authentication) context.Context {
	return context.WithValue(ctx, authenticationKey{}, auth)
}

func FromContext(ctx context.Context) (Authentication, bool) {
	auth, ok := ctx.Value(authenticationKey{}).(Authentication)
	return auth, ok
}
