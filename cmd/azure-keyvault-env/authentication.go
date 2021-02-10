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
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	"k8s.io/klog/v2"
)

func createHTTPClientWithTrustedCAAndMtls(caCert, clientCert, clientKey []byte) (*http.Client, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientKeyPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientKeyPair},
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

func getCredentials(useAuthService bool, authServiceAddress string, clientCertDir string) (credentialprovider.AzureKeyVaultCredentials, error) {
	if useAuthService {
		// caCert, clientCert, clientKey []byte
		caCert, err := ioutil.ReadFile(path.Join(clientCertDir, "ca.crt"))
		if err != nil {
			return nil, err
		}

		clientCert, err := ioutil.ReadFile(path.Join(clientCertDir, "tls.crt"))
		if err != nil {
			return nil, err
		}

		clientKey, err := ioutil.ReadFile(path.Join(clientCertDir, "tls.key"))
		if err != nil {
			return nil, err
		}

		client, err := createHTTPClientWithTrustedCAAndMtls(caCert, clientCert, clientKey)
		if err != nil {
			klog.ErrorS(err, "failed to download ca cert")
			os.Exit(1)
		}

		url := fmt.Sprintf("https://%s/auth/%s/%s", authServiceAddress, config.namespace, config.podName)
		klog.InfoS("requesting azure key vault oauth token", "url", url)

		res, err := client.Get(url)
		if err != nil {
			klog.ErrorS(err, "request token failed", "url", url)
			os.Exit(1)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get credentials, %s", res.Status)
		}

		var creds *credentialprovider.OAuthCredentials
		err = json.NewDecoder(res.Body).Decode(&creds)
		if err != nil {
			return nil, fmt.Errorf("failed to decode body, error %+v", err)
		}

		klog.InfoS("successfully received oauth token")
		return creds, nil
	}

	provider, err := credentialprovider.NewFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials provider for azure key vault, error %+v", err)
	}

	creds, err := provider.GetAzureKeyVaultCredentials()
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
		klog.ErrorS(err, "failed to decode base64 signature string")
		os.Exit(1)
	}

	signature := string(signatureArray)

	bPubKey, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		klog.ErrorS(err, "failed to decode base64 public key string")
		os.Exit(1)
	}

	pubKey := string(bPubKey)

	pubRsaKey, err := parseRsaPublicKey(pubKey)
	if err != nil {
		klog.ErrorS(err, "failed to parse rsa public key to verify args")
		os.Exit(1)
	}

	if !verifyPKCS(signature, origArgs, *pubRsaKey) {
		klog.ErrorS(fmt.Errorf("pkcs signature verification failed"), "args does not match original args defined by env-injector")
		os.Exit(1)
	}
}
