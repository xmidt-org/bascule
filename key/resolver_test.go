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
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/webpa-common/resource"
)

func TestSingleResolver(t *testing.T) {
	assert := assert.New(t)

	loader, err := (&resource.Factory{
		URI: publicKeyFilePath,
	}).NewLoader()

	if !assert.NoError(err) {
		return
	}

	expectedData, err := resource.ReadAll(loader)
	assert.NotEmpty(expectedData)
	assert.NoError(err)

	for _, purpose := range []Purpose{PurposeVerify, PurposeDecrypt, PurposeSign, PurposeEncrypt} {
		t.Logf("purpose: %s", purpose)

		expectedPair := &MockPair{}
		parser := &MockParser{}
		parser.On("ParseKey", mock.Anything, purpose, expectedData).Return(expectedPair, nil).Once()

		var resolver Resolver = &singleResolver{
			basicResolver: basicResolver{
				parser:  parser,
				purpose: purpose,
			},

			loader: loader,
		}

		assert.Contains(fmt.Sprintf("%s", resolver), publicKeyFilePath)

		pair, err := resolver.ResolveKey(context.Background(), "does not matter")
		assert.Equal(expectedPair, pair)
		assert.NoError(err)

		expectedPair.AssertExpectations(t)
		parser.AssertExpectations(t)
	}
}

func TestSingleResolverBadResource(t *testing.T) {
	assert := assert.New(t)

	var resolver Resolver = &singleResolver{
		basicResolver: basicResolver{
			parser:  DefaultParser,
			purpose: PurposeVerify,
		},
		loader: &resource.File{
			Path: "does not exist",
		},
	}

	key, err := resolver.ResolveKey(context.Background(), "does not matter")
	assert.Nil(key)
	assert.NotNil(err)
}

func TestMultiResolver(t *testing.T) {
	assert := assert.New(t)

	expander, err := (&resource.Factory{
		URI: publicKeyFilePathTemplate,
	}).NewExpander()

	if !assert.NoError(err) {
		return
	}

	loader, err := expander.Expand(
		map[string]interface{}{KeyIdParameterName: keyId},
	)
	assert.NoError(err)

	expectedData, err := resource.ReadAll(loader)
	assert.NotEmpty(expectedData)
	assert.NoError(err)

	for _, purpose := range []Purpose{PurposeVerify, PurposeDecrypt, PurposeSign, PurposeEncrypt} {
		t.Logf("purpose: %s", purpose)

		expectedPair := &MockPair{}
		parser := &MockParser{}
		parser.On("ParseKey", mock.Anything, purpose, expectedData).Return(expectedPair, nil).Once()

		var resolver Resolver = &multiResolver{
			basicResolver: basicResolver{
				parser:  parser,
				purpose: purpose,
			},
			expander: expander,
		}

		assert.Contains(fmt.Sprintf("%s", resolver), publicKeyFilePathTemplate)

		pair, err := resolver.ResolveKey(context.Background(), keyId)
		assert.Equal(expectedPair, pair)
		assert.NoError(err)

		expectedPair.AssertExpectations(t)
		parser.AssertExpectations(t)
	}
}

func TestMultiResolverBadResource(t *testing.T) {
	assert := assert.New(t)

	var resolver Resolver = &multiResolver{
		expander: &resource.Template{
			URITemplate: resource.MustParse("/this/does/not/exist/{key}"),
		},
	}

	key, err := resolver.ResolveKey(context.Background(), "this isn't valid")
	assert.Nil(key)
	assert.NotNil(err)
}

type badExpander struct {
	err error
}

func (bad *badExpander) Names() []string {
	return []string{}
}

func (bad *badExpander) Expand(interface{}) (resource.Loader, error) {
	return nil, bad.err
}

func TestMultiResolverBadExpander(t *testing.T) {
	assert := assert.New(t)

	expectedError := errors.New("The roof! The roof! The roof is on fire!")
	var resolver Resolver = &multiResolver{
		expander: &badExpander{expectedError},
	}

	key, err := resolver.ResolveKey(context.Background(), "does not matter")
	assert.Nil(key)
	assert.Equal(expectedError, err)
}
