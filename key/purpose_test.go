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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPurposeString(t *testing.T) {
	var testData = []struct {
		purpose        Purpose
		expectedString string
	}{
		{PurposeSign, "sign"},
		{PurposeVerify, "verify"},
		{PurposeEncrypt, "encrypt"},
		{PurposeDecrypt, "decrypt"},
		{Purpose(45), "verify"},
		{Purpose(-1), "verify"},
	}

	for _, test := range testData {
		actualString := test.purpose.String()
		if actualString != test.expectedString {
			t.Errorf("Expected String() [%s] but got [%s]", test.expectedString, actualString)
		}
	}
}

func TestPurposeMarshalJSON(t *testing.T) {
	var testData = []struct {
		purpose      Purpose
		expectedJSON string
	}{
		{PurposeSign, `"sign"`},
		{PurposeVerify, `"verify"`},
		{PurposeEncrypt, `"encrypt"`},
		{PurposeDecrypt, `"decrypt"`},
		{Purpose(45), `"verify"`},
		{Purpose(-1), `"verify"`},
	}

	for _, test := range testData {
		actualJSON, err := json.Marshal(test.purpose)
		if err != nil {
			t.Fatalf("Failed to marshal JSON: %v", err)
		}

		if string(actualJSON) != test.expectedJSON {
			t.Errorf("Expected JSON [%s] but got [%s]", test.expectedJSON, actualJSON)
		}
	}
}

func TestPurposeUnmarshalJSON(t *testing.T) {
	var validRecords = []struct {
		JSON            string
		expectedPurpose Purpose
	}{
		{`"sign"`, PurposeSign},
		{`"verify"`, PurposeVerify},
		{`"encrypt"`, PurposeEncrypt},
		{`"decrypt"`, PurposeDecrypt},
	}

	var invalidRecords = []string{
		"",
		"0",
		"123",
		`""`,
		`"invalid"`,
		`"SIGN"`,
		`"vERifY"`,
	}

	for _, test := range validRecords {
		var actualPurpose Purpose
		err := json.Unmarshal([]byte(test.JSON), &actualPurpose)
		if err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}

		if actualPurpose != test.expectedPurpose {
			t.Errorf("Expected purpose [%d] but got [%d]", test.expectedPurpose, actualPurpose)
		}
	}

	for _, invalidJSON := range invalidRecords {
		var actualPurpose Purpose
		err := json.Unmarshal([]byte(invalidJSON), &actualPurpose)
		if err == nil {
			t.Errorf("Should have failed to marshal JSON [%s]", invalidJSON)
		}
	}
}

func TestPurposeRequiresPrivateKey(t *testing.T) {
	assert := assert.New(t)

	var testData = []struct {
		purpose                    Purpose
		expectedRequiresPrivateKey bool
	}{
		{PurposeVerify, false},
		{PurposeSign, true},
		{PurposeEncrypt, true},
		{PurposeDecrypt, false},
	}

	for _, record := range testData {
		t.Logf("%#v", record)
		assert.Equal(record.expectedRequiresPrivateKey, record.purpose.RequiresPrivateKey())
	}
}
