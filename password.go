// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// Passworder is an optional interface that a Token may implement that
// provides access to an associated password.  Tokens derived from
// basic authentication will implement this interface.
type Passworder interface {
	// Password returns the password associated with this Token.
	Password() string
}

// GetPassword returns any password associated with the given Token.
//
// If the token implements Passworder, the result of the Password()
// method is returned along with true. Otherwise, this function returns
// the empty string and false to indicate that the Token did not carry
// an associated password.
func GetPassword(t Token) (password string, exists bool) {
	var p Passworder
	if TokenAs(t, &p) {
		password = p.Password()
		exists = true
	}

	return
}
