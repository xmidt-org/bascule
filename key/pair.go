/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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

package key

import (
	"crypto/rsa"
)

// Pair represents a resolved key pair.  For all Pair instances, the private key is optional,
// while the public key will always be present.
type Pair interface {
	// Purpose returns the configured intended usage of this key pair
	Purpose() Purpose

	// Public returns the public key associated with this pair.  It will never be nil
	Public() interface{}

	// HasPrivate tests whether this key Pair has a private key
	HasPrivate() bool

	// Private returns the optional private key associated with this Pair.  If there
	// is no private key, this method returns nil.
	Private() interface{}
}

// rsaPair is an RSA key Pair implementation
type rsaPair struct {
	purpose Purpose
	public  interface{}
	private *rsa.PrivateKey
}

func (rp *rsaPair) Purpose() Purpose {
	return rp.purpose
}

func (rp *rsaPair) Public() interface{} {
	return rp.public
}

func (rp *rsaPair) HasPrivate() bool {
	return rp.private != nil
}

func (rp *rsaPair) Private() interface{} {
	if rp.private != nil {
		return rp.private
	}

	return nil
}
