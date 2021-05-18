/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
