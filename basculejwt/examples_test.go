// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculejwt"
)

// newKeys returns a signing key and the key set a verifier would hold.
func newKeys() (jwk.Key, jwk.Set) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	private, err := jwk.Import[jwk.ECDSAPrivateKey](raw)
	if err != nil {
		panic(err)
	}

	_ = private.Set(jwk.KeyIDKey, "example")
	_ = private.Set(jwk.AlgorithmKey, jwa.ES256())

	public, err := private.PublicKey()
	if err != nil {
		panic(err)
	}

	keys := jwk.NewSet()
	_ = keys.AddKey(public)

	return private, keys
}

// sign produces a compact JWT from a builder.
func sign(key jwk.Key, b *jwt.Builder) string {
	token, err := b.Build()
	if err != nil {
		panic(err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), key))
	if err != nil {
		panic(err)
	}

	return string(signed)
}

// ExampleNewTokenParser parses a signed JWT.  The subject becomes the Token's
// principal, and a "capabilities" claim is exposed to approvers.
//
// In an HTTP service the parser is registered for the Bearer scheme with
// basculehttp.WithScheme rather than called directly.
func ExampleNewTokenParser() {
	key, keys := newKeys()

	parser, err := basculejwt.NewTokenParser(
		jwt.WithKeySet(keys), // jwk.NewCache serves a remote JWKS the same way
		jwt.WithIssuer("https://issuer.example.com"),
		jwt.WithAudience("my-service"),
	)
	if err != nil {
		panic(err)
	}

	raw := sign(key, jwt.NewBuilder().
		Issuer("https://issuer.example.com").
		Audience([]string{"my-service"}).
		Subject("joe").
		Expiration(time.Now().Add(time.Hour)).
		Claim(basculejwt.CapabilitiesKey, []string{
			"webpa-prefix-api:/device/.*/config:get",
			"webpa-prefix-cidr:10.0.0.0/8",
		}),
	)

	token, err := parser.Parse(context.Background(), raw)
	if err != nil {
		panic(err)
	}

	capabilities, _ := bascule.GetCapabilities(token)
	fmt.Println("principal:", token.Principal())
	fmt.Println("capabilities:", capabilities)

	// Output:
	// principal: joe
	// capabilities: [webpa-prefix-api:/device/.*/config:get webpa-prefix-cidr:10.0.0.0/8]
}

// ExampleNewTokenParser_rejected shows how to tell why a JWT was rejected
// without importing the underlying JWT library.
func ExampleNewTokenParser_rejected() {
	key, keys := newKeys()
	otherKey, _ := newKeys()

	parser, _ := basculejwt.NewTokenParser(
		jwt.WithKeySet(keys),
	)

	describe := func(raw string) {
		_, err := parser.Parse(context.Background(), raw)
		fmt.Printf("bad credentials: %t, expired: %t, signature: %t\n",
			errors.Is(err, bascule.ErrBadCredentials), // any rejection at all
			errors.Is(err, basculejwt.ErrExpired),
			errors.Is(err, basculejwt.ErrInvalidSignature),
		)
	}

	describe(sign(key, jwt.NewBuilder().
		Subject("joe").
		Expiration(time.Now().Add(-time.Hour)),
	))

	describe(sign(otherKey, jwt.NewBuilder().
		Subject("joe").
		Expiration(time.Now().Add(time.Hour)),
	))

	// Output:
	// bad credentials: true, expired: true, signature: false
	// bad credentials: true, expired: false, signature: true
}
