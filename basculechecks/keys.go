// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

var (
	capabilityKeys = []string{"capabilities"}
	partnerKeys    = []string{"allowedResources", "allowedPartners"}
)

// CapabilityKeys is the default location of capabilities in a bascule Token's
// Attributes.
func CapabilityKeys() []string {
	return capabilityKeys
}

// PartnerKeys is the location of the list of allowed partners in a bascule
// Token's Attributes.
func PartnerKeys() []string {
	return partnerKeys
}
