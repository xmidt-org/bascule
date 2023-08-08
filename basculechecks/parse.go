// SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package basculechecks

import (
	"regexp"
	"strings"
)

const Wildcard = "*"

// DeterminePartnerMetric takes a list of partners and decides what the partner
// metric label should be.
func DeterminePartnerMetric(partners []string) string {
	if len(partners) < 1 {
		return NonePartner
	}
	if len(partners) == 1 {
		if partners[0] == Wildcard {
			return WildcardPartner
		}
		return partners[0]
	}
	for _, partner := range partners {
		if partner == Wildcard {
			return WildcardPartner
		}
	}
	return ManyPartner
}

// determineEndpointMetric takes a list of regular expressions and applies them
// to the url of the request to decide what the endpoint metric label should be.
func determineEndpointMetric(endpoints []*regexp.Regexp, urlHit string) string {
	if len(endpoints) == 0 {
		return NoneEndpoint
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
	return NotRecognizedEndpoint
}
