// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Store is an in-memory, threadsafe Credentials implementation.
// A Store instance is safe for concurrent reads and writes.
// Instances of this type must not be copied after creation.
//
// The zero value of this type is valid and ready to use.
type Store struct {
	lock       sync.RWMutex
	principals Principals
}

var _ Matcher = (*Store)(nil)
var _ Credentials = (*Store)(nil)

// Len returns the number of principals contained in this Store.
func (s *Store) Len() (n int) {
	s.lock.RLock()
	n = s.principals.Len()
	s.lock.RUnlock()
	return
}

// Get returns the Digest associated with the principal.  This method
// returns false to indicate that the principal did not exist.
func (s *Store) Get(principal string) (d Digest, exists bool) {
	s.lock.RLock()
	d, exists = s.principals.Get(principal)
	s.lock.RUnlock()
	return
}

// Set adds or updates a principal's password.
func (s *Store) Set(principal string, d Digest) {
	clone := d.Copy()
	s.lock.Lock()

	if s.principals == nil {
		s.principals = make(Principals)
	}

	s.principals.Set(principal, clone)

	s.lock.Unlock()
}

// Delete removes the principal from this Store.  This method returns
// true if the deletion occurred, false if the principal didn't exist.
func (s *Store) Delete(principal string) (d Digest, existed bool) {
	s.lock.Lock()
	d, existed = s.principals.Delete(principal)
	s.lock.Unlock()
	return
}

// Update performs a bulk update to this Store. Copies are made of
// all digests before storing internally.
func (s *Store) Update(more Principals) {
	names := make([]string, 0, len(more))
	digests := make([]Digest, 0, len(more))
	for principal, digest := range more {
		names = append(names, principal)
		digests = append(digests, digest.Copy())
	}

	s.lock.Lock()

	if s.principals == nil {
		s.principals = make(Principals)
	}

	for i := 0; i < len(names); i++ {
		s.principals[names[i]] = digests[i] // a copy was already made
	}

	s.lock.Unlock()
}

// Matches tests if the given principal's hashed password matches the
// plaintext password.  This method returns true if both (1) the principal
// exists, and (2) the password matches.  If the principal does not exist,
// this method returns bascule.ErrBadCredentials.
func (s *Store) Matches(cmp Comparer, principal string, plaintext []byte) (err error) {
	s.lock.RLock()
	digest, exists := s.principals.Get(principal)
	s.lock.RUnlock()

	if exists {
		err = Matches(cmp, plaintext, digest)
	} else {
		err = fmt.Errorf("No such principal: %s", principal)
	}

	return
}

// MarshalJSON writes the current state of this Store to JSON.
func (s *Store) MarshalJSON() (data []byte, err error) {
	s.lock.RLock()
	data, err = json.Marshal(s.principals)
	s.lock.RUnlock()
	return
}

// UnmarshalJSON unmarshals data and replaces the current set of principals.
// If unmarshalling returned an error, this Store's state remains unchanged.
func (s *Store) UnmarshalJSON(data []byte) (err error) {
	s.lock.Lock()

	var unmarshaled Principals
	if err = json.Unmarshal(data, &unmarshaled); err == nil {
		s.principals = unmarshaled
	}

	s.lock.Unlock()

	return
}
