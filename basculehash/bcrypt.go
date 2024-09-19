// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"golang.org/x/crypto/bcrypt"
)

// Bcrypt is a Hasher and Comparer based around the bcrypt hashing
// algorithm.
type Bcrypt struct {
	// Cost is the cost parameter for bcrypt.  If unset, the internal
	// bcrypt cost is used.  If this value is higher than the max,
	// Hash will return an error.
	//
	// See: https://pkg.go.dev/golang.org/x/crypto/bcrypt#pkg-constants
	Cost int
}

var _ Hasher = Bcrypt{}
var _ Comparer = Bcrypt{}

// Hash executes the bcrypt algorithm and write the output to dst.
func (b Bcrypt) Hash(plaintext []byte) (Digest, error) {
	hashed, err := bcrypt.GenerateFromPassword(plaintext, b.Cost)
	return Digest(hashed), err
}

// Matches attempts to match a plaintext against its bcrypt hashed value.
func (b Bcrypt) Matches(plaintext []byte, hash Digest) error {
	return bcrypt.CompareHashAndPassword(hash, plaintext)
}
