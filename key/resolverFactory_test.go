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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/webpa-common/resource"
)

func TestBadURITemplates(t *testing.T) {
	assert := assert.New(t)

	badURITemplates := []string{
		"",
		"badscheme://foo/bar.pem",
		"http://badtemplate.com/{bad",
		"file:///etc/{too}/{many}/{parameters}",
		"http://missing.keyId.com/{someOtherName}",
	}

	for _, badURITemplate := range badURITemplates {
		t.Logf("badURITemplate: %s", badURITemplate)

		factory := ResolverFactory{
			Factory: resource.Factory{
				URI: badURITemplate,
			},
		}

		resolver, err := factory.NewResolver()
		assert.Nil(resolver)
		assert.NotNil(err)
	}
}

func TestResolverFactoryDefaultParser(t *testing.T) {
	assert := assert.New(t)

	parser := &MockParser{}
	resolverFactory := ResolverFactory{
		Factory: resource.Factory{
			URI: publicKeyFilePath,
		},
	}

	assert.Equal(DefaultParser, resolverFactory.parser())
	parser.AssertExpectations(t)
}

func TestResolverFactoryCustomParser(t *testing.T) {
	assert := assert.New(t)

	parser := &MockParser{}
	resolverFactory := ResolverFactory{
		Factory: resource.Factory{
			URI: publicKeyFilePath,
		},
		Parser: parser,
	}

	assert.Equal(parser, resolverFactory.parser())
	parser.AssertExpectations(t)
}
