// SPDX-FileCopyrightText: 2020 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// GetCapabilities returns the set of security capabilities associated
// with the given Token.
//
// If the given Token has a Capabilities method that returns a []string,
// that method is used to determine the capabilities.  Otherwise, this
// function returns an empty slice.
func GetCapabilities(t Token) (caps []string) {
	type capabilities interface {
		Capabilities() []string
	}

	if c, ok := t.(capabilities); ok {
		caps = c.Capabilities()
	}

	return
}
