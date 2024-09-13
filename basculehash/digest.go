// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehash

import "io"

// Digest is the result of applying a Hasher to plaintext.
// A digest must be valid UTF-8, preferably using the format
// described by https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md.
type Digest []byte

// Copy returns a distinct copy of this digest.
func (d Digest) Copy() Digest {
	clone := make(Digest, len(d))
	copy(clone, d)
	return clone
}

// String returns this Digest as is, but cast as a string.
func (d Digest) String() string {
	return string(d)
}

// MarshalText simply returns this Digest as a byte slice.  This method ensures
// that the digest is written as is instead of encoded as base64 or some other
// encoding.
func (d Digest) MarshalText() ([]byte, error) {
	return []byte(d), nil
}

// UnmarshalText uses the given text as is.
func (d *Digest) UnmarshalText(text []byte) error {
	*d = text
	return nil
}

// WriteTo writes this digest to the given writer.
func (d Digest) WriteTo(dst io.Writer) (int64, error) {
	c, err := dst.Write(d)
	return int64(c), err
}
