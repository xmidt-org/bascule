// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import "context"

// Credentials is a source of principals and their associated digests.  A
// credentials instance may be in-memory or a remote system.
type Credentials interface {
	// Get returns the Digest associated with the given Principal.
	// This method returns false if the principal did not exist.
	Get(ctx context.Context, principal string) (d Digest, exists bool)

	// Set associates a principal with a Digest.  If the principal already
	// exists, its digest is replaced.
	Set(ctx context.Context, principal string, d Digest)

	// Delete removes one or more principals from this set.
	Delete(ctx context.Context, principals ...string)

	// Update performs a bulk update of these credentials. Any existing
	// principals are replaced.
	Update(ctx context.Context, p Principals)
}
