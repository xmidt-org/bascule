// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculehttp

// fastIsSpace tests an ASCII byte to see if it's whitespace.
// HTTP headers are restricted to US-ASCII, so we don't need
// the full unicode stack.
func fastIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// fastContainsSpace uses fastIsSpace on each character in a string
// until it finds a space.
func fastContainsSpace(v string) bool {
	for i := 0; i < len(v); i++ {
		if fastIsSpace(v[i]) {
			return true
		}
	}

	return false
}
