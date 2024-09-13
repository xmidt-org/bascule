// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"sync"
)

// Store is an in-memory, threadsafe store of principals together with hashed
// password digests. A Store instance is safe for concurrent
// reads and writes. Instances of this type must not be copied after
// creation.
//
// The zero value of this type is valid and ready to use.
type Store struct {
	lock       sync.RWMutex
	principals Principals
}

// set updates the principals data under the lock.
// This internal method does not copy the digest.
func (s *Store) set(principal string, d Digest) {
	s.lock.Lock()
	s.principals.Set(principal, d)
	s.lock.Unlock()
}

// Set adds or updates a principal's password.
//
// This method does not retain d.  A distinct copy of the digest
// is made and used internally.
func (s *Store) Set(principal string, d Digest) {
	s.set(
		principal,
		d.Copy(),
	)
}

// Matches tests if the given principal's hashed password matches the
// plaintext password.  This method returns true if both (1) the principal
// exists, and (2) the password matches.  If either condition is false,
// this method returns false.
func (s *Store) Matches(cmp Comparer, principal string, plaintext []byte) (bool, error) {
	s.lock.RLock()
	digest, exists := s.principals.Get(principal)
	s.lock.RUnlock()

	if exists {
		return Matches(cmp, plaintext, digest)
	}

	return false, nil
}
