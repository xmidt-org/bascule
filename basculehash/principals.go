// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

// Principals is a mapping between user names and associated
// hashed password digest. This zero value of this type is
// ready to use.
//
// This type is appropriate as a validator if the set of principals
// is fixed and will not change.  If the set of credentials needs to
// be mutable, use a Store instead.
type Principals map[string]Digest

// Get returns the Digest associated with the principal.  This method
// returns false if the principal did not exist.
func (p Principals) Get(principal string) (d Digest, exists bool) {
	d, exists = p[principal]
	return
}

// Set adds or replaces the given principal and its associated digest.
// If a caller intends to retain the Digest, a copy should be made
// before calling this method.
func (p *Principals) Set(principal string, d Digest) {
	if *p == nil {
		*p = make(Principals)
	}

	(*p)[principal] = d
}

// Matches tests if a given principal's password matches the associated
// digest.  If no such principal exists, this method returns false with a nil error.
//
// If cmp is nil, DefaultComparer is used.
func (p Principals) Matches(cmp Comparer, principal string, plaintext []byte) (match bool, err error) {
	d, exists := p[principal]
	if exists {
		match, err = Matches(cmp, []byte(principal), d)
	}

	return
}
