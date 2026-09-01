// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculejwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)
	suite.testKey, err = jwk.Import[jwk.RSAPrivateKey](key)
	suite.Require().NoError(err)
	suite.Require().NoError(suite.testKey.Set(jwk.KeyIDKey, "test"))
	suite.Require().NoError(suite.testKey.Set(jwk.AlgorithmKey, jwa.RS256()))
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

	suite.signedJWT, err = jwt.Sign(suite.testJWT, jwt.WithKey(jwa.RS256(), suite.testKey))
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
		p, ok := token.Principal()
		suite.Require().True(ok)
		suite.Equal(suite.subject, p)
		caps, ok := bascule.GetCapabilities(token)
		suite.Equal(suite.capabilities, caps)
		suite.Require().True(ok)

		suite.Require().Implements((*bascule.AttributesAccessor)(nil), token)
		v, ok := bascule.GetAttribute[string](token.(bascule.AttributesAccessor), "version")
		suite.Require().True(ok)
		suite.Equal(suite.version, v)

		suite.Require().Implements((*Claims)(nil), token)
		claims := token.(Claims)
		v1, ok := claims.Audience()
		suite.Require().True(ok)
		suite.Equal(suite.audience, v1)
		v2, ok := claims.Subject()
		suite.Require().True(ok)
		suite.Equal(suite.subject, v2)
		v3, ok := claims.Issuer()
		suite.Require().True(ok)
		suite.Equal(suite.issuer, v3)
		v4, ok := claims.Expiration()
		suite.Require().True(ok)
		suite.Equal(suite.expiration, v4)
		v5, ok := claims.IssuedAt()
		suite.Require().True(ok)
		suite.Equal(suite.issuedAt, v5)
		v6, ok := claims.NotBefore()
		suite.Require().True(ok)
		suite.Equal(suite.notBefore, v6)
		v7, ok := claims.JwtID()
		suite.Require().True(ok)
		suite.Equal(suite.jwtID, v7)
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
