// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
)

const (
	// MaxSaltLength is the maximum number of bytes allowed
	// for salt by this package.
	MaxSaltLength = math.MaxUint8 // bytes
)

var (
	// ErrMaxSaltLengthExceeded is returned to indicate that the value
	// passed to Salter.Generate exceeded the maximum allowed value.
	ErrMaxSaltLengthExceeded = fmt.Errorf(
		"Salt length cannot exceed [%d] bytes",
		MaxSaltLength,
	)
)

// Salt is an initialization vector or just plain salt for a hash
// or other cryptographic algorithm.
type Salt []byte

// Write writes a simple, binary representation of this salt.  The raw
// salt is written to dst, prefixed with the length byte.
//
// If this salt is larger than MaxSaltLength, ErrMaxSaltLengthExceeded is returned.
func (s Salt) Write(dst io.Writer) (n int, err error) {
	switch {
	case len(s) > MaxSaltLength:
		err = ErrMaxSaltLengthExceeded

	default:
		// we only need (1) length byte
		var length [1]byte
		length[0] = uint8(len(s))

		var c int
		c, err = dst.Write(length[:])
		n += c

		if err == nil {
			c, err = dst.Write([]byte(s))
			n += c
		}
	}

	return
}

// Salter generates random salt.
type Salter interface {
	// Generate generates n bytes of random salt. If the
	// underlying source of randomness returned an error, that error
	// is returned by this method.
	//
	// If n is nonpositive, returns an empty slice with no error.
	// If n is larger than MaxSaltLength, an error is returned.
	Generate(n int) (Salt, error)
}

// defaultSalter is the default implementation of Salter.  This
// implementation uses crypto/rand.Reader as the source of randomness.
type defaultSalter struct{}

// Generate is the default implementation for this package.  It uses
// crypto/rand.Reader to generate n bytes of salt, returning an
// error is n exceeds MaxSaltLength.
func (defaultSalter) Generate(n int) (s Salt, err error) {
	switch {
	case n < 1:
		// do nothing

	case n > MaxSaltLength:
		err = ErrMaxSaltLengthExceeded

	default:
		s = make(Salt, n)
		_, err = io.ReadFull(rand.Reader, []byte(s))
	}

	return
}

// DefaultSalter returns the default Salter implementation.  The returned
// Salter uses crypto/rand.Reader as the source of randomness.
func DefaultSalter() Salter {
	return defaultSalter{}
}
