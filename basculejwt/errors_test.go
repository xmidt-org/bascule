// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type ErrorsTestSuite struct {
	suite.Suite

	key  jwk.Key
	keys jwk.Set
	now  time.Time
}

func (suite *ErrorsTestSuite) SetupSuite() {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)

	suite.key = suite.importKey(raw, "test")

	public, err := jwk.PublicKeyOf(suite.key)
	suite.Require().NoError(err)

	suite.keys = jwk.NewSet()
	suite.Require().NoError(suite.keys.AddKey(public))

	suite.now = time.Now()
}

// importKey turns a raw RSA key into a signing key with a key id and algorithm.
func (suite *ErrorsTestSuite) importKey(raw *rsa.PrivateKey, keyID string) jwk.Key {
	key, err := jwk.Import[jwk.RSAPrivateKey](raw)
	suite.Require().NoError(err)
	suite.Require().NoError(key.Set(jwk.KeyIDKey, keyID))
	suite.Require().NoError(key.Set(jwk.AlgorithmKey, jwa.RS256()))

	return key
}

// sign builds a token with the given claims and signs it with key.
func (suite *ErrorsTestSuite) sign(key jwk.Key, build func(*jwt.Builder) *jwt.Builder) string {
	token, err := build(jwt.NewBuilder().Subject("test")).Build()
	suite.Require().NoError(err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	suite.Require().NoError(err)

	return string(signed)
}

// parse runs a value through a parser built with the given options and returns
// the error, which must not be nil.
func (suite *ErrorsTestSuite) parse(value string, options ...jwt.ParseOption) error {
	parser, err := NewTokenParser(options...)
	suite.Require().NoError(err)

	token, err := parser.Parse(context.Background(), value)
	suite.Require().Error(err, "the value should not have parsed")
	suite.Nil(token)

	return err
}

// expires returns a builder for a token that is valid for an hour.
func (suite *ErrorsTestSuite) valid(b *jwt.Builder) *jwt.Builder {
	return b.Expiration(suite.now.Add(time.Hour))
}

func (suite *ErrorsTestSuite) TestExpired() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return b.IssuedAt(suite.now.Add(-2 * time.Hour)).Expiration(suite.now.Add(-time.Hour))
	})

	suite.ErrorIs(suite.parse(value, jwt.WithKeySet(suite.keys)), ErrExpired)
}

func (suite *ErrorsTestSuite) TestNotYetValid() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return b.NotBefore(suite.now.Add(time.Hour)).Expiration(suite.now.Add(2 * time.Hour))
	})

	suite.ErrorIs(suite.parse(value, jwt.WithKeySet(suite.keys)), ErrNotYetValid)
}

func (suite *ErrorsTestSuite) TestInvalidIssuedAt() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return b.IssuedAt(suite.now.Add(time.Hour)).Expiration(suite.now.Add(2 * time.Hour))
	})

	suite.ErrorIs(suite.parse(value, jwt.WithKeySet(suite.keys)), ErrInvalidIssuedAt)
}

func (suite *ErrorsTestSuite) TestInvalidIssuer() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return suite.valid(b.Issuer("wrong"))
	})

	suite.ErrorIs(
		suite.parse(value, jwt.WithKeySet(suite.keys), jwt.WithIssuer("expected")),
		ErrInvalidIssuer)
}

func (suite *ErrorsTestSuite) TestInvalidAudience() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return suite.valid(b.Audience([]string{"wrong"}))
	})

	suite.ErrorIs(
		suite.parse(value, jwt.WithKeySet(suite.keys), jwt.WithAudience("expected")),
		ErrInvalidAudience)
}

func (suite *ErrorsTestSuite) TestMissingClaim() {
	value := suite.sign(suite.key, suite.valid)

	suite.ErrorIs(
		suite.parse(value, jwt.WithKeySet(suite.keys), jwt.WithRequiredClaim("nonesuch")),
		ErrMissingClaim)
}

// TestMissingKey verifies a token whose key id is not in the key set is
// reported as an unverifiable signature.  This package cannot tell that apart
// from a wrong key, since the key provider belongs to the caller.
func (suite *ErrorsTestSuite) TestMissingKey() {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)

	value := suite.sign(suite.importKey(raw, "nonesuch"), suite.valid)

	suite.ErrorIs(suite.parse(value, jwt.WithKeySet(suite.keys)), ErrInvalidSignature)
}

func (suite *ErrorsTestSuite) TestMalformed() {
	suite.ErrorIs(suite.parse("this is not a jwt", jwt.WithVerify(false)), ErrMalformed)
}

// TestGeneralErrors verifies a returned error is joined with the general error
// describing the kind of failure, so that a caller may ask a coarse question
// instead of enumerating every specific one.
func (suite *ErrorsTestSuite) TestGeneralErrors() {
	suite.Run("ReadButNotAccepted", func() {
		value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
			return b.IssuedAt(suite.now.Add(-2 * time.Hour)).Expiration(suite.now.Add(-time.Hour))
		})

		err := suite.parse(value, jwt.WithKeySet(suite.keys))

		suite.ErrorIs(err, bascule.ErrBadCredentials)
		suite.NotErrorIs(err, bascule.ErrInvalidCredentials)
		suite.ErrorIs(err, ErrExpired, "the specific error is still reachable")
	})

	suite.Run("CouldNotBeRead", func() {
		err := suite.parse("this is not a jwt", jwt.WithVerify(false))

		suite.ErrorIs(err, bascule.ErrInvalidCredentials)
		suite.NotErrorIs(err, bascule.ErrBadCredentials)
		suite.ErrorIs(err, ErrMalformed, "the specific error is still reachable")
	})
}

// TestUnderlyingErrorRemains verifies that translating a failure does not hide
// the jwx error, for a caller that wants it.
func (suite *ErrorsTestSuite) TestUnderlyingErrorRemains() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return b.IssuedAt(suite.now.Add(-2 * time.Hour)).Expiration(suite.now.Add(-time.Hour))
	})

	err := suite.parse(value, jwt.WithKeySet(suite.keys))

	suite.ErrorIs(err, ErrExpired)
	suite.ErrorIs(err, jwt.TokenExpiredError{}, "the jwx error must still be reachable")
}

// TestNotFromParse verifies a failure that did not come from jwt.Parse is
// returned unchanged, rather than being described as a malformed token.
func (suite *ErrorsTestSuite) TestNotFromParse() {
	original := context.Canceled

	got := translate(original)
	suite.Require().NotNil(got)
	suite.Same(original, got)

	suite.Nil(translate(nil))
}

// TestCancellationIsNotACredentialProblem verifies a request that was canceled
// or timed out is returned unchanged.  The token may be perfectly good; what
// failed was the attempt to check it.
func (suite *ErrorsTestSuite) TestCancellationIsNotACredentialProblem() {
	for _, original := range []error{context.Canceled, context.DeadlineExceeded} {
		suite.Run(original.Error(), func() {
			got := translate(original)

			suite.Equal(original, got, "the failure must be returned unchanged")
			suite.NotErrorIs(got, bascule.ErrBadCredentials)
			suite.NotErrorIs(got, bascule.ErrInvalidCredentials)
		})
	}
}

// TestMalformedIsOnlyMalformed verifies ErrMalformed is reported for a value
// that could not be read, and not for failures the claims or signature explain.
func (suite *ErrorsTestSuite) TestMalformedIsOnlyMalformed() {
	suite.Run("Garbage", func() {
		err := suite.parse("this is not a jwt", jwt.WithVerify(false))

		suite.ErrorIs(err, ErrMalformed)
		suite.ErrorIs(err, bascule.ErrInvalidCredentials)
	})

	suite.Run("Expired", func() {
		value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
			return b.IssuedAt(suite.now.Add(-2 * time.Hour)).Expiration(suite.now.Add(-time.Hour))
		})

		err := suite.parse(value, jwt.WithKeySet(suite.keys))

		suite.NotErrorIs(err, ErrMalformed, "an expired token is well formed")
		suite.ErrorIs(err, ErrExpired)
	})
}

// TestUnderlyingErrorAlwaysReachable verifies the jwx error survives
// translation for a recognized failure too.  A caller may need it, or an error
// its own key provider produced, which reaches it through the same chain.
func (suite *ErrorsTestSuite) TestUnderlyingErrorAlwaysReachable() {
	value := suite.sign(suite.key, func(b *jwt.Builder) *jwt.Builder {
		return b.IssuedAt(suite.now.Add(-2 * time.Hour)).Expiration(suite.now.Add(-time.Hour))
	})

	err := suite.parse(value, jwt.WithKeySet(suite.keys))

	suite.ErrorIs(err, ErrExpired)
	suite.ErrorIs(err, jwt.TokenExpiredError{}, "the jwx error must still be reachable")
}

func TestErrors(t *testing.T) {
	suite.Run(t, new(ErrorsTestSuite))
}

// contextObserver records the context a key provider is handed.
type contextObserver struct {
	got context.Context
}

func (o *contextObserver) FetchKeys(ctx context.Context, _ jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
	o.got = ctx

	return errors.New("the provider should not have been reached")
}

// TestContextIsHonored verifies the caller's context governs parsing.  A key
// provider may reach out to a remote key set, and a request that is over should
// not keep doing that.
func (suite *ErrorsTestSuite) TestContextIsHonored() {
	value := suite.sign(suite.key, suite.valid)

	suite.Run("Canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		observer := new(contextObserver)
		parser, err := NewTokenParser(jwt.WithKeyProvider(observer))
		suite.Require().NoError(err)

		token, err := parser.Parse(ctx, value)
		suite.Nil(token)
		suite.Require().Error(err)

		suite.ErrorIs(err, context.Canceled)
		suite.Nil(observer.got, "parsing should stop before a key is fetched")
		suite.NotErrorIs(err, bascule.ErrBadCredentials,
			"an abandoned check is not a judgement about the token")
	})

	suite.Run("Live", func() {
		observer := new(contextObserver)
		parser, err := NewTokenParser(jwt.WithKeyProvider(observer))
		suite.Require().NoError(err)

		_, err = parser.Parse(context.Background(), value)
		suite.Require().Error(err)

		suite.Require().NotNil(observer.got, "a live context should reach the provider")
		suite.NoError(observer.got.Err())
	})
}
