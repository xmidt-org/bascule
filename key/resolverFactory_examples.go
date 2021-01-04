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
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
)

const (
	keyID = "examplekey"
)

func setupExamples() (string, string) {
	currentDirectory, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to obtain current working directory: %v\n", err)
		os.Exit(1)
	}

	httpServer := httptest.NewServer(http.FileServer(http.Dir(currentDirectory)))
	defer httpServer.Close()
	fmt.Printf("started test server at %s\n", httpServer.URL)

	publicKeyURL := fmt.Sprintf("%s/%s.pub", httpServer.URL, keyID)
	publicKeyURLTemplate := fmt.Sprintf("%s/{%s}.pub", httpServer.URL, KeyIdParameterName)

	return publicKeyURL, publicKeyURLTemplate
}

func ExampleSingleKeyConfiguration() {
	publicKeyURL, _ := setupExamples()
	jsonConfiguration := fmt.Sprintf(`{
		"uri": "%s",
		"purpose": "verify",
		"header": {
			"Accept": ["text/plain"]
		}
	}`, publicKeyURL)

	var factory ResolverFactory
	if err := json.Unmarshal([]byte(jsonConfiguration), &factory); err != nil {
		fmt.Println(err)
		return
	}

	resolver, err := factory.NewResolver()
	if err != nil {
		fmt.Println(err)
		return
	}

	// althrough we pass a keyId, it doesn't matter
	// the keyId would normally come from a JWT or other source, but
	// this configuration maps all key identifiers onto the same resource
	key, err := resolver.ResolveKey(context.Background(), keyID)
	if err != nil {
		fmt.Println(err)
		return
	}

	publicKey, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println("Expected a public key")
	}

	fmt.Printf("%#v", publicKey)

	// Output:
	// &rsa.PublicKey{N:27943075365309976493653163303797959212418241538912650140443307384472696765226993413692820781465849081859025776428168351053450151991381458393395627926945090025279037554792902370352660829719944448435879538779506598037701785142079839040587119599241554109043386957121126327267661933261531301157240649436180239359321477795441956911062536999488590278721548425004681839069551715529565117581358421070795577996947939534909344145027536788621293233751031126681790089555592380957432236272148722403554429033227913702251021698422165616430378445527162280875770582636410571931829939754369601100687471071175959731316949515587341982201, E:65537}
}

func ExampleURITemplateConfiguration() {
	_, publicKeyURLTemplate := setupExamples()
	jsonConfiguration := fmt.Sprintf(`{
		"uri": "%s",
		"purpose": "verify",
		"header": {
			"Accept": ["text/plain"]
		}
	}`, publicKeyURLTemplate)

	var factory ResolverFactory
	if err := json.Unmarshal([]byte(jsonConfiguration), &factory); err != nil {
		fmt.Println(err)
		return
	}

	resolver, err := factory.NewResolver()
	if err != nil {
		fmt.Println(err)
		return
	}

	key, err := resolver.ResolveKey(context.Background(), keyID)
	if err != nil {
		fmt.Println(err)
		return
	}

	publicKey, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println("Expected a public key")
	}

	fmt.Printf("%#v", publicKey)

	// Output:
	// &rsa.PublicKey{N:27943075365309976493653163303797959212418241538912650140443307384472696765226993413692820781465849081859025776428168351053450151991381458393395627926945090025279037554792902370352660829719944448435879538779506598037701785142079839040587119599241554109043386957121126327267661933261531301157240649436180239359321477795441956911062536999488590278721548425004681839069551715529565117581358421070795577996947939534909344145027536788621293233751031126681790089555592380957432236272148722403554429033227913702251021698422165616430378445527162280875770582636410571931829939754369601100687471071175959731316949515587341982201, E:65537}
}
