package jwtvalidator

import (
	"errors"
	"time"

	"github.com/SermoDigital/jose/jwt"
)

var (
	ErrorNoProtectedHeader = errors.New("Missing protected header")
	ErrorNoSigningMethod   = errors.New("Signing method (alg) is missing or unrecognized")
)

// JWTValidatorFactory is a configurable factory for *jwt.Validator instances
type JWTValidatorFactory struct {
	Expected  jwt.Claims `json:"expected"`
	ExpLeeway int        `json:"expLeeway"`
	NbfLeeway int        `json:"nbfLeeway"`
}

func (f *JWTValidatorFactory) expLeeway() time.Duration {
	if f.ExpLeeway > 0 {
		return time.Duration(f.ExpLeeway) * time.Second
	}

	return 0
}

func (f *JWTValidatorFactory) nbfLeeway() time.Duration {
	if f.NbfLeeway > 0 {
		return time.Duration(f.NbfLeeway) * time.Second
	}

	return 0
}

// New returns a jwt.Validator using the configuration expected claims (if any)
// and a validator function that checks the exp and nbf claims.
//
// The SermoDigital library doesn't appear to do anything with the EXP and NBF
// members of jwt.Validator, but this Factory Method populates them anyway.
func (f *JWTValidatorFactory) New(custom ...jwt.ValidateFunc) *jwt.Validator {
	expLeeway := f.expLeeway()
	nbfLeeway := f.nbfLeeway()

	var validateFunc jwt.ValidateFunc
	customCount := len(custom)
	if customCount > 0 {
		validateFunc = func(claims jwt.Claims) (err error) {
			now := time.Now()
			err = claims.Validate(now, expLeeway, nbfLeeway)
			for index := 0; index < customCount && err == nil; index++ {
				err = custom[index](claims)
			}

			return
		}
	} else {
		// if no custom validate functions were passed, use a simpler function
		validateFunc = func(claims jwt.Claims) (err error) {
			now := time.Now()
			err = claims.Validate(now, expLeeway, nbfLeeway)

			return
		}
	}

	return &jwt.Validator{
		Expected: f.Expected,
		EXP:      expLeeway,
		NBF:      nbfLeeway,
		Fn:       validateFunc,
	}
}
