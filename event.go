// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// NoCredentialsEvent is dispatched when a source does not have any
// credentials.
type NoCredentialsEvent[S any] struct {
	Source S
	Err    error
}

// TokenParsedEvent is dispatched when a Token is successfully created from
// the source, but has not yet been authenticated.
type TokenParsedEvent[S any] struct {
	Source S
	Token  Token
}

// AuthenticateFailedEvent indicates an attempt to authenticate a Token
// has failed.  The Err field will have more detailed information.
type AuthenticateFailedEvent[S any] struct {
	Source S
	Token  Token
	Err    error
}

// AuthenticateEvent indicates that a Token has been extracted from the
// source and has been successfully authenticated (validated).
//
// No authorization has been done when this event is dispatched.
type AuthenticateEvent[S any] struct {
	Source S
	Token  Token
}

// AuthorizeFailedEvent indicates that a token was not authorized to
// access a given resource.
type AuthorizeFailedEvent[S, R any] struct {
	Source   S
	Resource R
	Token    Token
	Err      error
}

// AuthorizeEvent indicates that a token was successfully authorized
// to access a given resource.
type AuthorizeEvent[S, R any] struct {
	Source   S
	Resource R
	Token    Token
}
