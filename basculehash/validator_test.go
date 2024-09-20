// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/bascule"
	"golang.org/x/crypto/bcrypt"
)

type validatorTestToken struct {
	principal, password string
}

func (t validatorTestToken) Principal() string { return t.principal }

func (t validatorTestToken) Password() string { return t.password }

type ValidatorTestSuite struct {
	TestSuite

	testCtx context.Context
	request *http.Request
}

func (suite *ValidatorTestSuite) SetupSubTest() {
	suite.SetupTest()
}

func (suite *ValidatorTestSuite) SetupTest() {
	suite.TestSuite.SetupTest()
	suite.testCtx = context.Background()
	suite.request = httptest.NewRequest("GET", "/", nil)
}

// newDefaultToken creates a password token using this suite's default plaintext.
func (suite *ValidatorTestSuite) newDefaultToken(principal string) bascule.Token {
	return validatorTestToken{
		principal: principal,
		password:  string(suite.plaintext),
	}
}

// newCredentials builds a standard set of credentials using the given hasher.
func (suite *ValidatorTestSuite) newCredentials(h Hasher) Credentials {
	return Principals{
		"joe":  suite.goodHash(h.Hash(suite.plaintext)),
		"fred": suite.goodHash(h.Hash(suite.plaintext)),
	}
}

func (suite *ValidatorTestSuite) newValidator(cmp Comparer, creds Credentials) bascule.Validator[*http.Request] {
	v := NewValidator[*http.Request](cmp, creds)
	suite.Require().NotNil(v)
	return v
}

func (suite *ValidatorTestSuite) testValidate(cmp Comparer, h Hasher) {
	v := suite.newValidator(cmp, suite.newCredentials(h))

	suite.Run("NonPasswordToken", func() {
		t := bascule.StubToken("joe")
		next, err := v.Validate(suite.testCtx, suite.request, t)
		suite.Equal(t, next)
		suite.NoError(err)
	})

	suite.Run("NoSuchPrincipal", func() {
		t := suite.newDefaultToken("nosuch")
		next, err := v.Validate(suite.testCtx, suite.request, t)
		suite.Equal(t, next)
		suite.ErrorIs(err, bascule.ErrBadCredentials)
	})

	suite.Run("BadPassword", func() {
		t := validatorTestToken{principal: "joe", password: "bad"}
		next, err := v.Validate(suite.testCtx, suite.request, t)
		suite.Equal(t, next)
		suite.ErrorIs(err, bascule.ErrBadCredentials)
	})

	suite.Run("Success", func() {
		t := suite.newDefaultToken("joe")
		next, err := v.Validate(suite.testCtx, suite.request, t)
		suite.Equal(t, next)
		suite.NoError(err)
	})
}

func (suite *ValidatorTestSuite) TestValidate() {
	suite.Run("DefaultComparer", func() {
		suite.testValidate(nil, Default())
	})

	suite.Run("CustomComparer", func() {
		hc := Bcrypt{Cost: bcrypt.MinCost}
		suite.testValidate(hc, hc)
	})
}

func TestValidator(t *testing.T) {
	suite.Run(t, new(ValidatorTestSuite))
}
