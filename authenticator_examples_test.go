// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"context"
	"fmt"
)

type Extra struct {
	Name string
	Age  int
}

func (e Extra) Principal() string { return e.Name }

// ExampleJoinTokens_augment shows how to augment a Token as part
// of authentication workflow.
func ExampleJoinTokens_augment() {
	original := StubToken("original")
	authenticator, _ := NewAuthenticator[string](
		WithTokenParsers(
			StubTokenParser[string]{
				Token: original,
			},
		),
		WithValidators(
			AsValidator[string](
				func(t Token) (Token, error) {
					// augment this token with extra information
					return JoinTokens(t, Extra{Name: "extra", Age: 33}), nil
				},
			),
		),
	)

	authenticated, _ := authenticator.Authenticate(
		context.Background(),
		"source",
	)

	fmt.Println("authenticated principal:", authenticated.Principal())

	var extra Extra
	if !TokenAs(authenticated, &extra) {
		panic("token cannot be converted")
	}

	fmt.Println("extra.Name:", extra.Name)
	fmt.Println("extra.Age:", extra.Age)

	// Output:
	// authenticated principal: original
	// extra.Name: extra
	// extra.Age: 33
}

// ExampleWithAuthenticateListeners observes every authentication attempt,
// successful or not.  This is the hook for audit logs and metrics.
func ExampleWithAuthenticateListeners() {
	authenticator, _ := NewAuthenticator[string](
		WithTokenParsers(
			AsTokenParser[string](func(source string) (Token, error) {
				if source == "" {
					return nil, ErrMissingCredentials
				}

				return StubToken(source), nil
			}),
		),
		WithAuthenticateListenerFuncs(
			func(e AuthenticateEvent[string]) {
				if e.Err != nil {
					fmt.Printf("denied  source=%q err=%v\n", e.Source, e.Err)
					return
				}

				fmt.Printf("allowed source=%q principal=%s\n", e.Source, e.Token.Principal())
			},
		),
	)

	_, _ = authenticator.Authenticate(context.Background(), "joe")
	_, _ = authenticator.Authenticate(context.Background(), "")

	// Output:
	// allowed source="joe" principal=joe
	// denied  source="" err=missing credentials
}
