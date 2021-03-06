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
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func makeNonKeyPEMBlock() []byte {
	block := pem.Block{
		Type:  "NOT A KEY",
		Bytes: []byte{1, 2, 3, 4, 5},
	}

	return pem.EncodeToMemory(&block)
}

func TestDefaultParser(t *testing.T) {
	assert := assert.New(t)

	var testData = []struct {
		keyFilePath   string
		purpose       Purpose
		expectPrivate bool
	}{
		{publicKeyFilePath, PurposeVerify, false},
		{privateKeyFilePath, PurposeEncrypt, true},
		{privateKeyFilePath, PurposeSign, true},
		{publicKeyFilePath, PurposeDecrypt, false},
	}

	for _, record := range testData {
		t.Logf("%v", record)

		data, err := ioutil.ReadFile(record.keyFilePath)
		if !assert.NoError(err) {
			continue
		}

		pair, err := DefaultParser.ParseKey(context.Background(), record.purpose, data)
		if !assert.NoError(err) && !assert.NotNil(pair) {
			continue
		}

		assert.NotNil(pair.Public())
		assert.Equal(record.expectPrivate, pair.HasPrivate())
		assert.Equal(record.expectPrivate, pair.Private() != nil)
		assert.Equal(record.purpose, pair.Purpose())
	}
}

func TestDefaultParserString(t *testing.T) {
	assert := assert.New(t)
	assert.NotEmpty(fmt.Sprintf("%s", DefaultParser))
}

func TestDefaultParserNoPEM(t *testing.T) {
	assert := assert.New(t)

	notPEM := []byte{9, 9, 9}
	pair, err := DefaultParser.ParseKey(context.Background(), PurposeVerify, notPEM)
	assert.Nil(pair)
	assert.Equal(ErrorPEMRequired, err)
}

func TestDefaultParserInvalidPublicKey(t *testing.T) {
	assert := assert.New(t)

	for _, purpose := range []Purpose{PurposeVerify, PurposeDecrypt} {
		t.Logf("%s", purpose)
		pair, err := DefaultParser.ParseKey(context.Background(), purpose, makeNonKeyPEMBlock())
		assert.Nil(pair)
		assert.NotNil(err)
	}
}

func TestDefaultParserInvalidPrivateKey(t *testing.T) {
	assert := assert.New(t)

	for _, purpose := range []Purpose{PurposeSign, PurposeEncrypt} {
		t.Logf("%s", purpose)
		pair, err := DefaultParser.ParseKey(context.Background(), purpose, makeNonKeyPEMBlock())
		assert.Nil(pair)
		assert.Equal(ErrorUnsupportedPrivateKeyFormat, err)
	}
}
