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
	"os"
	"path"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
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

func createMtlsClient(clientCertDir string) (*http.Client, error) {
	// caCert, clientCert, clientKey []byte
	caCert, err := os.ReadFile(path.Join(clientCertDir, "ca.crt"))
	if err != nil {
		return nil, err
	}

	clientCert, err := os.ReadFile(path.Join(clientCertDir, "tls.crt"))
	if err != nil {
		return nil, err
	}

	clientKey, err := os.ReadFile(path.Join(clientCertDir, "tls.key"))
	if err != nil {
		return nil, err
	}

	client, err := createHTTPClientWithTrustedCAAndMtls(caCert, clientCert, clientKey)
	if err != nil {
		klog.ErrorS(err, "failed to download ca cert")
		os.Exit(1)
	}

	return client, nil
}

func getCredentials() (azure.LegacyTokenCredential, string, error) {
	provider, err := credentialprovider.NewFromEnvironment()
	if err != nil {
		return nil, "", fmt.Errorf("failed to create credentials provider for azure key vault, error: %w", err)
	}

	creds, err := provider.GetAzureKeyVaultCredentials()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get credentials for azure key vault, error: %w", err)
	}
	return creds, provider.GetAzureKeyVaultDNSSuffix(), nil
}

func getCredentialsIdentity() (azure.LegacyTokenCredential, string, error) {
	provider, err := credentialprovider.NewFromAzidentity()
	if err != nil {
		return nil, "", fmt.Errorf("failed to create credentials provider for azure key vault, error: %w", err)
	}

	creds, err := provider.GetAzureKeyVaultCredentials()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get credentials for azure key vault, error: %w", err)
	}
	return creds, provider.GetAzureKeyVaultDNSSuffix(), nil
}

func getCredentialsAuthService(authServiceAddress string, authServiceValidationAddress string, clientCertDir string) (azure.LegacyTokenCredential, error) {
	startupCACert, err := os.ReadFile(path.Join(clientCertDir, "ca.crt"))
	if err != nil {
		return nil, err
	}

	validationUrl := fmt.Sprintf("%s/auth/%s/%s?secret=%s", authServiceValidationAddress, config.namespace, config.podName, config.authServiceSecret)
	klog.InfoS("checking if current auth service credentials are stale", "url", validationUrl)

	stale := false
	valClient := &http.Client{
		Timeout: time.Second * 10,
	}
	valRes, err := valClient.Get(validationUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to check for stale credentials: %w", err)
	}
	defer valRes.Body.Close()

	if valRes.StatusCode == http.StatusOK {
		klog.InfoS("auth service credentials ok", "url", validationUrl)
	} else if valRes.StatusCode == http.StatusCreated {
		klog.InfoS("auth service credentials were stale, but now updated - expect some time before the pod gets updated with the new secret", "url", validationUrl)
		stale = true
	} else {
		klog.ErrorS(nil, "failed to validate credentials", "url", validationUrl, "status", valRes.Status, "statusCode", valRes.StatusCode)
		return nil, fmt.Errorf("failed to validate credentials, got http status code %v", valRes.StatusCode)
	}

	if stale {
		klog.InfoS("checking for updated credentials", "retryTimes", 20)
		err = retry(20, time.Second*5, func() error {
			currentCACert, err := os.ReadFile(path.Join(clientCertDir, "ca.crt"))
			if err != nil {
				return err
			}

			if string(startupCACert) == string(currentCACert) {
				return fmt.Errorf("credentials are still stale")
			}

			klog.InfoS("credentials updated - good to go!")
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("credentials was never updated, failedTimes: %v, err: %w", 20, err)
		}
	}

	client, err := createMtlsClient(clientCertDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create mtls http client, err: %w", err)
	}

	url := fmt.Sprintf("%s/auth/%s/%s", authServiceAddress, config.namespace, config.podName)
	klog.InfoS("requesting azure key vault oauth token", "url", url)

	res, err := client.Get(url)
	if err != nil {
		klog.ErrorS(err, "request token failed", "url", url)
		return nil, fmt.Errorf("request token failed, err: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		klog.ErrorS(err, "failed to get credentials", "url", url, "status", res.Status, "statusCode", res.StatusCode)
		return nil, fmt.Errorf("request token failed with status code %v", res.StatusCode)
	}

	var creds *credentialprovider.OAuthCredentials
	err = json.NewDecoder(res.Body).Decode(&creds)
	if err != nil {
		return nil, fmt.Errorf("failed to decode body, error %w", err)
	}

	klog.InfoS("successfully received oauth token")
	return azure.NewLegacyTokenCredentialOauth(creds.OAuthToken), nil
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
	return nil, fmt.Errorf("key type is not RSA")
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
