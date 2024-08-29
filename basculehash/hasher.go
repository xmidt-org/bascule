// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"io"
)

// Hasher is a strategy for one-way hashing.
type Hasher interface {
	// Hash writes the hash of a plaintext to a writer.  The number of
	// bytes written along with any error is returned.
	//
	// The format of the written hash must be ASCII.  Typically, base64
	// encoding will be used to achieve this.
	//
	// This method should write out any hash parameters necessary to
	// execute the same hash against a different plaintext.  This allows
	// a Comparer to work, for example.  It also allows migration of
	// hash parameters in a way that doesn't disturb already hashed values.
	Hash(dst io.Writer, plaintext []byte) (int, error)
}
