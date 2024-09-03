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
	// The format of the written hash must be ASCII. The recommended
	// format is the modular crypt format, which bcrypt uses.
	Hash(dst io.Writer, plaintext []byte) (int, error)
}
