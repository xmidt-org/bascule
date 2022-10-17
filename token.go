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

// package bascule provides a token interface and basic implementation, which
// can be validated and added and taken from a context.  Some basic checks
// which can be used to validate are also provided.
package bascule

// Token is the behavior supplied by all secure tokens
type Token interface {
	// Type is the custom token type assigned by plugin code
	Type() string

	// Principal is the security principal, e.g. the user name or client id
	Principal() string

	// Attributes are an arbitrary set of name/value pairs associated with the token.
	// Typically, these will be filled with information supplied by the user, e.g. the claims of a JWT.
	Attributes() Attributes
}

// Attributes is the interface that wraps methods which dictate how to interact
// with a token's attributes. Getter functions return a boolean as second element
// which indicates that a value of the requested type exists at the given key path.
type Attributes interface {
	Get(key string) (interface{}, bool)
}

// simpleToken is a very basic token type that can serve as the Token for many types of secure pipelines
type simpleToken struct {
	tokenType  string
	principal  string
	attributes Attributes
}

func (st simpleToken) Type() string {
	return st.tokenType
}

func (st simpleToken) Principal() string {
	return st.principal
}

func (st simpleToken) Attributes() Attributes {
	return st.attributes
}

// NewToken creates a Token from basic information.  Many secure pipelines can use the returned value as
// their token.  Specialized pipelines can create additional interfaces and augment the returned Token
// as desired.  Alternatively, some pipelines can simply create their own Tokens out of whole cloth.
func NewToken(tokenType, principal string, attributes Attributes) Token {
	return simpleToken{tokenType, principal, attributes}
}
