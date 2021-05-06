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

import (
	"regexp"
	"strings"
)

// DeterminePartnerMetric takes a list of partners and decides what the partner
// metric label should be.
func DeterminePartnerMetric(partners []string) string {
	if len(partners) < 1 {
		return "none"
	}
	if len(partners) == 1 {
		if partners[0] == "*" {
			return "wildcard"
		}
		return partners[0]
	}
	for _, partner := range partners {
		if partner == "*" {
			return "wildcard"
		}
	}
	return "many"
}

// determineEndpointMetric takes a list of regular expressions and applies them
// to the url of the request to decide what the endpoint metric label should be.
func determineEndpointMetric(endpoints []*regexp.Regexp, urlHit string) string {
	if len(endpoints) == 0 {
		return "no_endpoints"
	}
	for _, r := range endpoints {
		idxs := r.FindStringIndex(urlHit)
		if len(idxs) == 0 {
			continue
		}
		if idxs[0] == 0 {
			return strings.ReplaceAll(r.String(), " ", "_")
		}
	}
	return "not_recognized"
}
