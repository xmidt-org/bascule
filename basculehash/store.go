// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"
	"encoding/json"
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

var _ Credentials = (*Store)(nil)

// Get returns the Digest associated with the principal.
func (s *Store) Get(ctx context.Context, principal string) (d Digest, exists bool) {
	s.lock.RLock()
	d, exists = s.principals.Get(ctx, principal)
	s.lock.RUnlock()
	return
}

// Set adds or updates a principal's password.
func (s *Store) Set(ctx context.Context, principal string, d Digest) {
	clone := d.Copy()
	s.lock.Lock()

	if s.principals == nil {
		s.principals = make(Principals)
	}

	s.principals.Set(ctx, principal, clone)

	s.lock.Unlock()
}

// Delete removes the principal(s) from this Store.
func (s *Store) Delete(_ context.Context, principals ...string) {
	s.lock.Lock()

	for _, toDelete := range principals {
		delete(s.principals, toDelete)
	}

	s.lock.Unlock()
}

// Update performs a bulk update to this Store.
func (s *Store) Update(_ context.Context, more Principals) {
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
