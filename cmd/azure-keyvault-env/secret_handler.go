/*
Copyright Sparebanken Vest

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2alpha1"

	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
)

// EnvSecretHandler handles getting and formatting secrets from Azure Key Vault to environment variables
type EnvSecretHandler interface {
	Handle() (string, error)
}

// AzureKeyVaultSecretHandler handles getting and formatting Azure Key Vault Secret from Azure Key Vault to environment variables
type AzureKeyVaultSecretHandler struct {
	secretSpec    *akv.AzureKeyVaultSecret
	vaultService  vault.Service
	transformator transformers.Transformator
	query         string
}

// AzureKeyVaultCertificateHandler handles getting and formatting Azure Key Vault Certificate from Azure Key Vault to environment variables
type AzureKeyVaultCertificateHandler struct {
	secretSpec   *akv.AzureKeyVaultSecret
	vaultService vault.Service
	query        string
}

// AzureKeyVaultKeyHandler handles getting and formatting Azure Key Vault Key from Azure Key Vault to environment variables
type AzureKeyVaultKeyHandler struct {
	secretSpec   *akv.AzureKeyVaultSecret
	vaultService vault.Service
	query        string
}

// AzureKeyVaultMultiValueSecretHandler handles getting and formatting Azure Key Vault Secret containing multiple values from Azure Key Vault to Kubernetes
type AzureKeyVaultMultiValueSecretHandler struct {
	secretSpec   *akv.AzureKeyVaultSecret
	vaultService vault.Service
	query        string
}

// NewAzureKeyVaultSecretHandler return a new AzureKeyVaultSecretHandler
func NewAzureKeyVaultSecretHandler(secretSpec *akv.AzureKeyVaultSecret, query string, transformator transformers.Transformator, vaultService vault.Service) *AzureKeyVaultSecretHandler {
	return &AzureKeyVaultSecretHandler{
		secretSpec:    secretSpec,
		vaultService:  vaultService,
		transformator: transformator,
		query:         query,
	}
}

// NewAzureKeyVaultCertificateHandler return a new AzureKeyVaultCertificateHandler
func NewAzureKeyVaultCertificateHandler(secretSpec *akv.AzureKeyVaultSecret, query string, vaultService vault.Service) *AzureKeyVaultCertificateHandler {
	return &AzureKeyVaultCertificateHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
		query:        query,
	}
}

// NewAzureKeyVaultKeyHandler returns a new AzureKeyVaultKeyHandler
func NewAzureKeyVaultKeyHandler(secretSpec *akv.AzureKeyVaultSecret, query string, vaultService vault.Service) *AzureKeyVaultKeyHandler {
	return &AzureKeyVaultKeyHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
		query:        query,
	}
}

// NewAzureKeyVaultMultiKeySecretHandler returns a new AzureKeyVaultMultiKeySecretHandler
func NewAzureKeyVaultMultiKeySecretHandler(secretSpec *akv.AzureKeyVaultSecret, query string, vaultService vault.Service) *AzureKeyVaultMultiValueSecretHandler {
	return &AzureKeyVaultMultiValueSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
		query:        query,
	}
}

// Handle getting and formating Azure Key Vault Secret from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultSecretHandler) Handle() (string, error) {
	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return "", err
	}

	secret, err = h.transformator.Transform(secret)
	if err != nil {
		return "", err
	}

	switch h.query {
	case "":
		return secret, nil
	case corev1.BasicAuthUsernameKey:
		creds := strings.Split(secret, ":")
		if len(creds) != 2 {
			return "", fmt.Errorf("unable to handle azure key vault env secret as basic auth - check that formatting is correct 'username:password'")
		}
		return creds[0], nil

	case corev1.BasicAuthPasswordKey:
		creds := strings.Split(secret, ":")
		if len(creds) != 2 {
			return "", fmt.Errorf("unable to handle azure key vault secret as basic auth - check that formatting is correct 'username:password'")
		}
		return creds[1], nil

	default:
		return "", fmt.Errorf("unable to handle azure key vault secret with query '%s' - query is not valid", h.query)
	}
}

// Handle getting and formating Azure Key Vault Certificate from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultCertificateHandler) Handle() (string, error) {
	options := vault.CertificateOptions{
		ExportPrivateKey:  h.query == corev1.TLSPrivateKeyKey,
		EnsureServerFirst: h.secretSpec.Spec.Output.Secret.ChainOrder == "ensureserverfirst",
	}

	cert, err := h.vaultService.GetCertificate(&h.secretSpec.Spec.Vault, &options)

	if err != nil {
		return "", err
	}

	if h.query == "raw" {
		return string(cert.ExportRaw()), nil
	}

	var privKey []byte
	var pubKey []byte

	if options.ExportPrivateKey {
		if privKey, err = cert.ExportPrivateKeyAsPem(); err != nil {
			return "", err
		}
		return string(privKey), nil
	}

	if pubKey, err = cert.ExportPublicKeyAsPem(); err != nil {
		return "", err
	}
	return string(pubKey), nil
}

// Handle getting and formating Azure Key Vault Key from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultKeyHandler) Handle() (string, error) {
	key, err := h.vaultService.GetKey(&h.secretSpec.Spec.Vault)
	if err != nil {
		return "", err
	}

	return key, nil
}

// Handle getting and formating Azure Key Vault Secret containing mulitple values from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultMultiValueSecretHandler) Handle() (string, error) {
	if h.secretSpec.Spec.Vault.Object.ContentType == "" {
		return "", fmt.Errorf("cannot use '%s' without also specifying content type", akv.AzureKeyVaultObjectTypeMultiKeyValueSecret)
	}

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return "", err
	}

	var dat map[string]string

	switch h.secretSpec.Spec.Vault.Object.ContentType {
	case akv.AzureKeyVaultObjectContentTypeJSON:
		if err := json.Unmarshal([]byte(secret), &dat); err != nil {
			return "", err
		}
	case akv.AzureKeyVaultObjectContentTypeYaml:
		if err := yaml.Unmarshal([]byte(secret), &dat); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("content type '%s' not supported", h.secretSpec.Spec.Vault.Object.ContentType)
	}

	if val, ok := dat[h.query]; ok {
		return val, nil
	}

	return "", fmt.Errorf("key '%s' not found in azure key vault secret '%s' of type '%s'", h.query, h.secretSpec.Spec.Vault.Object.Name, h.secretSpec.Spec.Vault.Object.ContentType)
}
