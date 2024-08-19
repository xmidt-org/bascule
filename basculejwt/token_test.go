// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
)

type TokenTestSuite struct {
	suite.Suite

	audience []string
	jwtID    string
	issuer   string

	expiration time.Time
	issuedAt   time.Time
	notBefore  time.Time
	subject    string

	capabilities     []string
	allowedResources map[string]any
	version          string

	testKey    jwk.Key
	testKeySet jwk.Set

	testJWT   jwt.Token
	signedJWT []byte
}

func (suite *TokenTestSuite) initializeKey() {
	var err error
	suite.testKey, err = jwk.ParseKey([]byte(`{
    "p": "7HMYtb-1dKyDp1OkdKc9WDdVMw3vtiiKDyuyRwnnwMOoYLPYxqE0CUMzw8_zXuzq7WJAmGiFd5q7oVzkbHzrtQ",
    "kty": "RSA",
    "q": "5253lCAgBLr8SR_VzzDtk_3XTHVmVIgniajMl7XM-ttrUONV86DoIm9VBx6ywEKpj5Xv3USBRNlpf8OXqWVhPw",
    "d": "G7RLbBiCkiZuepbu46G0P8J7vn5l8G6U78gcMRdEhEsaXGZz_ZnbqjW6u8KI_3akrBT__GDPf8Hx8HBNKX5T9jNQW0WtJg1XnwHOK_OJefZl2fnx-85h3tfPD4zI3m54fydce_2kDVvqTOx_XXdNJD7v5TIAgvCymQv7qvzQ0VE",
    "e": "AQAB",
    "use": "sig",
    "kid": "test",
    "qi": "a_6YlMdA9b6piRodA0MR7DwjbALlMan19wj_VkgZ8Xoilq68sGaV2CQDoAdsTW9Mjt5PpCxvJawz0AMr6LIk9w",
    "dp": "s55HgiGs_YHjzSOsBXXaEv6NuWf31l_7aMTf_DkZFYVMjpFwtotVFUg4taJuFYlSeZwux9h2s0IXEOCZIZTQFQ",
    "alg": "RS256",
    "dq": "M79xoX9laWleDAPATSnFlbfGsmP106T2IkPKK4oNIXJ6loWerHEoNrrqKkNk-LRvMZn3HmS4-uoaOuVDPi9bBQ",
    "n": "1cHjMu7H10hKxnoq3-PJT9R25bkgVX1b39faqfecC82RMcD2DkgCiKGxkCmdUzuebpmXCZuxp-rVVbjrnrI5phAdjshZlkHwV0tyJOcerXsPgu4uk_VIJgtLdvgUAtVEd8-ZF4Y9YNOAKtf2AHAoRdP0ZVH7iVWbE6qU-IN2los"
}`))

	suite.Require().NoError(err)

	suite.testKeySet = jwk.NewSet()
	err = suite.testKeySet.AddKey(suite.testKey)
	suite.Require().NoError(err)
}

func (suite *TokenTestSuite) initializeClaims() {
	suite.audience = []string{"test-audience"}
	suite.jwtID = "test-jwt"
	suite.issuer = "test-issuer"

	// time fields in the JOSE spec are in seconds
	// generate an issuedAt in the recent past, so that validation can work
	suite.issuedAt = time.Now().Add(-time.Second).Round(time.Second).UTC()
	suite.expiration = suite.issuedAt.Add(time.Hour)
	suite.notBefore = suite.issuedAt.Add(-time.Hour)

	suite.subject = "test-subject"

	suite.capabilities = []string{
		"x1:webpa:api:.*:all",
		"x1:webpa:api:device/.*/config\\b:all",
	}

	suite.allowedResources = make(map[string]any)
	suite.allowedResources["allowedPartners"] = []string{"comcast"}

	suite.version = "2.0"
}

func (suite *TokenTestSuite) createJWT() {
	var err error
	suite.testJWT, err = jwt.NewBuilder().
		Audience(suite.audience).
		Subject(suite.subject).
		IssuedAt(suite.issuedAt).
		Expiration(suite.expiration).
		NotBefore(suite.notBefore).
		JwtID(suite.jwtID).
		Issuer(suite.issuer).
		Claim("capabilities", suite.capabilities).
		Claim("allowedResources", suite.allowedResources).
		Claim("version", suite.version).
		Build()

	suite.Require().NoError(err)

	suite.signedJWT, err = jwt.Sign(suite.testJWT, jwt.WithKey(jwa.RS256, suite.testKey))
	suite.Require().NoError(err)
}

func (suite *TokenTestSuite) SetupSuite() {
	suite.initializeKey()
	suite.initializeClaims()
	suite.createJWT()

	suite.T().Log("using signed JWT", string(suite.signedJWT))
}

func (suite *TokenTestSuite) TestTokenParser() {
	suite.Run("Success", func() {
		tp, err := NewTokenParser(jwt.WithKeySet(suite.testKeySet))
		suite.Require().NoError(err)
		suite.Require().NotNil(tp)

		token, err := tp.Parse(context.Background(), string(suite.signedJWT))
		suite.Require().NoError(err)
		suite.Require().NotNil(token)

		suite.Equal(suite.subject, token.Principal())
		caps, ok := bascule.GetCapabilities(token)
		suite.Equal(suite.capabilities, caps)
		suite.True(ok)

		suite.Require().Implements((*bascule.AttributesAccessor)(nil), token)
		v, ok := bascule.GetAttribute[string](token.(bascule.AttributesAccessor), "version")
		suite.True(ok)
		suite.Equal(suite.version, v)

		suite.Require().Implements((*Claims)(nil), token)
		claims := token.(Claims)
		suite.Equal(suite.audience, claims.Audience())
		suite.Equal(suite.subject, claims.Subject())
		suite.Equal(suite.issuer, claims.Issuer())
		suite.Equal(suite.expiration, claims.Expiration())
		suite.Equal(suite.issuedAt, claims.IssuedAt())
		suite.Equal(suite.notBefore, claims.NotBefore())
		suite.Equal(suite.jwtID, claims.JwtID())
	})

	suite.Run("NoOptions", func() {
		tp, err := NewTokenParser()
		suite.Require().NoError(err)
		suite.Require().NotNil(tp)

		token, err := tp.Parse(context.Background(), string(suite.signedJWT))
		suite.Error(err)
		suite.Nil(token)
	})
}

func TestToken(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}
