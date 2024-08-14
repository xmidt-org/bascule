package bascule

import "context"

// AuthenticateEvent represents the result of bascule's authenticate workflow.
type AuthenticateEvent[S any] struct {
	// Source is the object that was parsed to produce the token.
	// This field is always set.
	Source S

	// Token is the token that resulted from parsing the source.  This field
	// will only be set if parsing was successful.
	Token Token

	// Err is the error that resulted from authentication.  This field will be
	// nil for a successful authentication.
	Err error
}

// Authenticator provides bascule's authentication workflow.  This type handles
// parsing tokens, validating them, and dispatching authentication events to listeners.
type Authenticator[S any] struct {
	listeners  Listeners[AuthenticateEvent[S]]
	parsers    TokenParsers[S]
	validators Validators[S]
}

// Authenticate implements bascule's authentication pipeline.  The following steps are
// performed:
//
// (1) The token is extracted from the source using the configured parser(s)
// (2) The token is validated using any configured validator(s)
// (3) Appropriate events are dispatched to listeners after either of steps (1) or (2)
func (a *Authenticator[S]) Authenticate(ctx context.Context, source S) (token Token, err error) {
	token, err = a.parsers.Parse(ctx, source)
	if err == nil {
		var next Token
		next, err = a.validators.Validate(ctx, source, token)
		if next != nil {
			token = next
		}
	}

	a.listeners.OnEvent(AuthenticateEvent[S]{
		Source: source,
		Token:  token,
		Err:    err,
	})

	return
}
