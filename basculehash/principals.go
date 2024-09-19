// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import "fmt"

// Principals is a Credentials implementation that is a simple map
// of principals to digests.  This type is not safe for concurrent
// usage.
//
// This type is appropriate if the set of credentials is either immutable
// or protected from concurrent updates by some other means.
type Principals map[string]Digest

var _ Matcher = Principals{}
var _ Credentials = Principals{}

// Len returns the number of principals in this set.
func (p Principals) Len() int {
	return len(p)
}

// Get returns the Digest associated with the principal.  This method
// returns false if the principal did not exist.
func (p Principals) Get(principal string) (d Digest, exists bool) {
	d, exists = p[principal]
	return
}

// Set adds or replaces the given principal and its associated digest.
func (p Principals) Set(principal string, d Digest) {
	p[principal] = d.Copy()
}

// Delete removes the given principal from this set, returning any existing
// Digest and an indicator of whether it existed.
func (p Principals) Delete(principal string) (d Digest, existed bool) {
	if d, existed = (p)[principal]; existed {
		delete(p, principal)
	}

	return
}

// Update performs a bulk update of credentials. Each digest is copied
// before storing in this instance.
func (p Principals) Update(more Principals) {
	for principal, digest := range more {
		p[principal] = digest.Copy()
	}
}

// Matches tests if a given principal's password matches the associated
// digest.  If no such principal exists, this method returns bascule.ErrBadCredentials.
//
// If cmp is nil, DefaultComparer is used.
func (p Principals) Matches(cmp Comparer, principal string, plaintext []byte) (err error) {
	if d, exists := p[principal]; exists {
		err = Matches(cmp, plaintext, d)
	} else {
		err = fmt.Errorf("No such principal: %s", principal)
	}

	return
}
