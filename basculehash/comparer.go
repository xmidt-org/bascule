// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

// Comparer is a strategy for comparing plaintext values with a
// hash value from a Hasher.
type Comparer interface {
	// Matches tests if the given plaintext matches the given hash.
	// For example, this method can test if a password matches the
	// one-way hashed password from a config file or database.
	//
	// If this method returns true, the error will always be nil.
	// If this method returns false, the error may be non-nil to
	// indicate that the match failed due to a problem, such as
	// the hash not being parseable.  Client code that is just
	// interested in a yes/no answer can disregard the error return.
	Matches(plaintext, hash []byte) (bool, error)
}
