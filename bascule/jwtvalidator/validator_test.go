package jwtvalidator

import (
	"errors"
	"testing"
	"time"

	"github.com/SermoDigital/jose/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWTValidatorFactory(t *testing.T) {
	assert := assert.New(t)
	now := time.Now().Unix()

	var testData = []struct {
		claims      jwt.Claims
		factory     JWTValidatorFactory
		expectValid bool
	}{
		{
			claims:      jwt.Claims{},
			factory:     JWTValidatorFactory{},
			expectValid: true,
		},
		{
			claims: jwt.Claims{
				"exp": now + 3600,
			},
			factory:     JWTValidatorFactory{},
			expectValid: true,
		},
		{
			claims: jwt.Claims{
				"exp": now - 3600,
			},
			factory:     JWTValidatorFactory{},
			expectValid: false,
		},
		{
			claims: jwt.Claims{
				"exp": now - 200,
			},
			factory: JWTValidatorFactory{
				ExpLeeway: 300,
			},
			expectValid: true,
		},
		{
			claims: jwt.Claims{
				"nbf": now + 3600,
			},
			factory:     JWTValidatorFactory{},
			expectValid: false,
		},
		{
			claims: jwt.Claims{
				"nbf": now - 3600,
			},
			factory:     JWTValidatorFactory{},
			expectValid: true,
		},
		{
			claims: jwt.Claims{
				"nbf": now + 200,
			},
			factory: JWTValidatorFactory{
				NbfLeeway: 300,
			},
			expectValid: true,
		},
	}

	for _, record := range testData {
		t.Logf("%#v", record)

		{
			t.Log("Simple case: no custom validate functions")
			validator := record.factory.New()
			assert.NotNil(validator)
			mockJWS := &mockJWS{}
			mockJWS.On("Claims").Return(record.claims).Once()

			err := validator.Validate(mockJWS)
			assert.Equal(record.expectValid, err == nil)

			mockJWS.AssertExpectations(t)
		}

		{
			for _, firstResult := range []error{nil, errors.New("first error")} {
				first := func(jwt.Claims) error {
					return firstResult
				}

				{
					t.Logf("One custom validate function returning: %v", firstResult)
					validator := record.factory.New(first)
					assert.NotNil(validator)
					mockJWS := &mockJWS{}
					mockJWS.On("Claims").Return(record.claims).Once()

					err := validator.Validate(mockJWS)
					assert.Equal(record.expectValid && firstResult == nil, err == nil)

					mockJWS.AssertExpectations(t)
				}

				for _, secondResult := range []error{nil, errors.New("second error")} {
					second := func(jwt.Claims) error {
						return secondResult
					}

					{
						t.Logf("Two custom validate functions returning: %v, %v", firstResult, secondResult)
						validator := record.factory.New(first, second)
						assert.NotNil(validator)
						mockJWS := &mockJWS{}
						mockJWS.On("Claims").Return(record.claims).Once()

						err := validator.Validate(mockJWS)
						assert.Equal(
							record.expectValid && firstResult == nil && secondResult == nil,
							err == nil,
						)

						mockJWS.AssertExpectations(t)
					}
				}
			}
		}
	}
}
