// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

// Hasher is a strategy for one-way hashing.
//
// Comparer is the interface for comparing hash digests with plaintext.
// A given Comparer will correspond to the format written by a Hasher.
type Hasher interface {
	// Hash returns a digest of the given plaintext.  The returned Digest
	// must be recognizable to a Comparer in order to be validated.
	//
	// If this method returns a nil error, it MUST return a valid Digest.
	// If this method returns an error, the Digest is not guaranteed to have
	// any particular value and should be discarded.
	//
	// The format of the digest must be ASCII. The recommended format is
	// the PHC format documented at:
	//
	// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
	Hash(plaintext []byte) (Digest, error)
}

// Comparer is a strategy for comparing plaintext values with a
// hash digest from a Hasher.
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
	Matches(plaintext []byte, d Digest) (bool, error)
}

// HasherComparer provides both hashing and corresponding comparison.
// This is the typical interface that a hashing algorithm will implement.
type HasherComparer interface {
	Hasher
	Comparer
}

var defaultHash HasherComparer = Bcrypt{}

// Default returns the default algorithm to use for comparing
// hashed passwords.
func Default() HasherComparer {
	return defaultHash
}

// Matches tests if the given Comparer strategy indicates a match
// between the plaintext and the digest.  If cmp is nil, the
// DefaultComparer() is used.
func Matches(cmp Comparer, plaintext []byte, d Digest) (bool, error) {
	if cmp == nil {
		cmp = Default()
	}

	return cmp.Matches(plaintext, d)
}
