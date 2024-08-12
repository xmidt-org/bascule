// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// CapabilitiesAccessor is an interface that a Token may choose to implement
// in order to provide access to any capabilities associated with the token.
// Capabilities do not make sense for all tokens, e.g. simple basic auth tokens.
type CapabilitiesAccessor interface {
	// Capabilities returns the set of capabilities associated with this token.
	Capabilities() []string
}

// GetCapabilities examines a Token to see if it provides capabilities, i.e.
// implements the CapabilitiesAccessor interface.  If it does, those capabilities
// are returned.  Otherwise, an empty slice is returned.
//
// If the Token implemented CapabilitiesAccessor, this method always returns true
// as its second return.  This allows a caller to disambiguate the cases of (1)
// a Token not implementing CapabilitiesAccessor, and (2) a Token implementing
// CapabilitiesAccessor but actually having no capabilities.
func GetCapabilities(t Token) (caps []string, ok bool) {
	var ca CapabilitiesAccessor
	ca, ok = t.(CapabilitiesAccessor)
	if ok {
		caps = ca.Capabilities()
	}

	return
}
