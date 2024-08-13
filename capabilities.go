// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package bascule

// CapabilitiesAccessor is an interface that any type may choose to implement
// in order to provide access to any capabilities associated with the token.
// Capabilities do not make sense for all tokens, e.g. simple basic auth tokens.
type CapabilitiesAccessor interface {
	// Capabilities returns the set of capabilities associated with this token.
	Capabilities() []string
}

// GetCapabilities attempts to convert a value v into a slice of capabilities.
//
// This function provide very flexible values to be used as capabilities.  This is
// particularly useful when unmarshalling values, since those values may not be strings
// or slices.
//
// The following conversions are attempted, in order:
//
// (1) If v implements CapabilitiesAccessor, then Capabilities() is returned.
//
// (2) If v is a []string, it is returned as is.
//
// (3) If v is a scalar string, a slice containing only that string is returned.
//
// (4) If v is a []any, a slice containing each element cast to a string is returned.
// If any elements are not castable to string, this function considers that to be the
// same as missing capabilities, i.e. false is returned with an empty slice.
//
// If any conversion was possible, this function returns true even if the capabilities were empty.
// If no such conversion was possible, this function returns false.
func GetCapabilities(v any) (caps []string, ok bool) {
	switch vt := v.(type) {
	case CapabilitiesAccessor:
		caps = vt.Capabilities()
		ok = true

	case []string:
		caps = vt
		ok = true

	case string:
		caps = []string{vt}
		ok = true

	case []any:
		converted := make([]string, 0, len(vt))
		for _, raw := range vt {
			if element, isString := raw.(string); isString {
				converted = append(converted, element)
			} else {
				break
			}
		}

		if ok = len(converted) == len(vt); ok {
			caps = converted
		}
	}

	return
}
