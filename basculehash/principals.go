// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import (
	"context"
)

// Principals is a Credentials implementation that is a simple map
// of principals to digests.  This type is not safe for concurrent
// usage.
//
// This type is appropriate if the set of credentials is either immutable
// or protected from concurrent updates by some other means.
type Principals map[string]Digest

var _ Credentials = Principals{}

// Get returns the Digest associated with the principal.  This method
// returns false if the principal did not exist.
func (p Principals) Get(ctx context.Context, principal string) (d Digest, exists bool) {
	if err := ctx.Err(); err != nil {
		return nil, false
	}

	d, exists = p[principal]
	return
}

// Set adds or replaces the given principal and its associated digest.
func (p Principals) Set(ctx context.Context, principal string, d Digest) {
	if err := ctx.Err(); err != nil {
		return
	}

	p[principal] = d.Copy()
}

// Delete removes the given principal(s) from this set.
func (p Principals) Delete(ctx context.Context, principals ...string) {
	if err := ctx.Err(); err != nil {
		return
	}

	for _, toDelete := range principals {
		delete(p, toDelete)
	}
}

// Update performs a bulk update of credentials. Each digest is copied
// before storing in this instance.
func (p Principals) Update(ctx context.Context, more Principals) {
	if err := ctx.Err(); err != nil {
		return
	}

	for principal, digest := range more {
		p[principal] = digest.Copy()
	}
}
