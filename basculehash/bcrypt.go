// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"io"

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

// Hash executes the bcrypt algorithm and write the output to dst.
func (b Bcrypt) Hash(dst io.Writer, plaintext []byte) (n int, err error) {
	hashed, err := bcrypt.GenerateFromPassword(plaintext, b.Cost)
	if err == nil {
		n, err = dst.Write(hashed)
	}

	return
}

// Matches attempts to match a plaintext against its bcrypt hashed value.
func (b Bcrypt) Matches(plaintext, hash []byte) (ok bool, err error) {
	err = bcrypt.CompareHashAndPassword(hash, plaintext)
	ok = (err == nil)
	return
}
