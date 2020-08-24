// Copyright © 2020 Sparebanken Vest
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Note: Code is based on bank-vaults from Banzai Cloud
//       (https://github.com/banzaicloud/bank-vaults)

package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
)

func createHTTPClientWithTrustedCA(caCert []byte) (*http.Client, error) {
	// caURL := fmt.Sprintf("http://%s/ca", host)
	// client := &http.Client{
	// 	Timeout: time.Second * 10,
	// }

	// res, err := client.Get(caURL)
	// if err != nil {
	// 	return nil, err
	// }

	// defer res.Body.Close()
	// caCert, err := ioutil.ReadAll(res.Body)
	// if err != nil {
	// 	return nil, err
	// }
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConf := &tls.Config{
		RootCAs: caCertPool,
	}
	tlsConf.BuildNameToCertificate()

	tlsClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: tlsConf,
		},
	}
	return tlsClient, nil
}

func getCredentials(useAuthService bool, authServiceAddress, caCert string) (azure.Credentials, error) {
	if useAuthService {
		client, err := createHTTPClientWithTrustedCA([]byte(caCert))
		if err != nil {
			logger.Fatalf("failed to download ca cert, error: %+v", err)
		}

		url := fmt.Sprintf("https://%s/auth/%s/%s", authServiceAddress, config.namespace, config.podName)
		logger.Infof("requesting azure key vault oauth token from %s", url)

		res, err := client.Get(url)
		if err != nil {
			logger.Fatalf("request token failed from %s, error: %+v", url, err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get credentials, %s", res.Status)
		}

		var creds azure.OAuthCredentials
		err = json.NewDecoder(res.Body).Decode(&creds)

		if err != nil {
			return nil, fmt.Errorf("failed to decode body, error %+v", err)
		}

		return creds, nil
	}

	creds, err := azure.NewFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials for azure key vault, error %+v", err)
	}
	return creds, nil
}

func verifyPKCS(signature string, plaintext string, pubkey rsa.PublicKey) bool {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hashed := sha256.Sum256([]byte(plaintext))
	err := rsa.VerifyPKCS1v15(&pubkey, crypto.SHA256, hashed[:], sig)
	return err == nil
}

func parseRsaPublicKey(pubPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing public signing key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, fmt.Errorf("Key type is not RSA")
}

func validateArgsSignature(origArgs, signatureB64, pubKeyBase64 string) {
	signatureArray, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		logger.Fatalf("failed to decode base64 signature string, error: %+v", err)
	}

	signature := string(signatureArray)

	bPubKey, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		logger.Fatalf("failed to decode base64 public key string, error: %+v", err)
	}

	pubKey := string(bPubKey)

	pubRsaKey, err := parseRsaPublicKey(pubKey)
	if err != nil {
		logger.Fatalf("failed to parse rsa public key to verify args: %+v", err)
	}

	if !verifyPKCS(signature, origArgs, *pubRsaKey) {
		logger.Fatal("args does not match original args defined by env-injector")
	}
}
