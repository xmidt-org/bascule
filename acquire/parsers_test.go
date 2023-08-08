// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRawTokenParser(t *testing.T) {
	assert := assert.New(t)
	payload := []byte("eyJhbGciOiJSUzI1NiIsImtpZCI6ImRldmVsb3BtZW50IiwidHlwIjoiSldUIn0.eyJhbGxvd2VkUmVzb3VyY2VzIjp7ImFsbG93ZWRQYXJ0bmVycyI6WyJjb21jYXN0Il19LCJhdWQiOiJYTWlEVCIsImNhcGFiaWxpdGllcyI6WyJ4MTppc3N1ZXI6dGVzdDouKjphbGwiLCJ4MTppc3N1ZXI6dWk6YWxsIl0sImV4cCI6MTYyMjE1Nzk4MSwiaWF0IjoxNjIyMDcxNTgxLCJpc3MiOiJkZXZlbG9wbWVudCIsImp0aSI6ImN4ZmkybTZDWnJjaFNoZ1Nzdi1EM3ciLCJuYmYiOjE2MjIwNzE1NjYsInBhcnRuZXItaWQiOiJjb21jYXN0Iiwic3ViIjoiY2xpZW50LXN1cHBsaWVkIiwidHJ1c3QiOjEwMDB9.7QzRWJgxGs1cEZunMOewYCnEDiq2CTDh5R5F47PYhkMVb2KxSf06PRRGN-rQSWPhhBbev1fGgu63mr3yp_VDmdVvHR2oYiKyxP2skJTSzfQmiRyLMYY5LcLn3BObyQxU8EnLhnqGIjpORW0L5Dd4QsaZmXRnkC73yGnJx4XCx0I")
	token, err := RawTokenParser(payload)
	assert.Equal(string(payload), token)
	assert.Nil(err)
}

func TestRawExpirationParser(t *testing.T) {
	tcs := []struct {
		Description  string
		Payload      []byte
		ShouldFail   bool
		ExpectedTime time.Time
	}{
		{
			Description: "Not a JWT",
			Payload:     []byte("xyz==abcNotAJWT"),
			ShouldFail:  true,
		},
		{
			Description:  "A jwt",
			Payload:      []byte("eyJhbGciOiJSUzI1NiIsImtpZCI6ImRldmVsb3BtZW50IiwidHlwIjoiSldUIn0.eyJhbGxvd2VkUmVzb3VyY2VzIjp7ImFsbG93ZWRQYXJ0bmVycyI6WyJjb21jYXN0Il19LCJhdWQiOiJYTWlEVCIsImNhcGFiaWxpdGllcyI6WyJ4MTppc3N1ZXI6dGVzdDouKjphbGwiLCJ4MTppc3N1ZXI6dWk6YWxsIl0sImV4cCI6MTYyMjE1Nzk4MSwiaWF0IjoxNjIyMDcxNTgxLCJpc3MiOiJkZXZlbG9wbWVudCIsImp0aSI6ImN4ZmkybTZDWnJjaFNoZ1Nzdi1EM3ciLCJuYmYiOjE2MjIwNzE1NjYsInBhcnRuZXItaWQiOiJjb21jYXN0Iiwic3ViIjoiY2xpZW50LXN1cHBsaWVkIiwidHJ1c3QiOjEwMDB9.7QzRWJgxGs1cEZunMOewYCnEDiq2CTDh5R5F47PYhkMVb2KxSf06PRRGN-rQSWPhhBbev1fGgu63mr3yp_VDmdVvHR2oYiKyxP2skJTSzfQmiRyLMYY5LcLn3BObyQxU8EnLhnqGIjpORW0L5Dd4QsaZmXRnkC73yGnJx4XCx0I"),
			ExpectedTime: time.Unix(1622157981, 0),
		},
	}

	for _, tc := range tcs {
		assert := assert.New(t)
		exp, err := RawTokenExpirationParser(tc.Payload)
		if tc.ShouldFail {
			assert.NotNil(err)
			assert.Empty(exp)
		} else {
			assert.Nil(err)
			assert.Equal(tc.ExpectedTime, exp)
		}
	}
}
