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
	"os"
	"strings"

	akvsv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
)

// EnvSecretHandler handles getting and formatting secrets from Azure Key Vault to environment variables
type EnvSecretHandler interface {
	Handle() (map[string]string, error)
}

// AzureKeyVaultSecretHandler handles getting and formatting Azure Key Vault Secret from Azure Key Vault to environment variables
type AzureKeyVaultSecretHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureKeyVaultCertificateHandler handles getting and formatting Azure Key Vault Certificate from Azure Key Vault to environment variables
type AzureKeyVaultCertificateHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureKeyVaultKeyHandler handles getting and formatting Azure Key Vault Key from Azure Key Vault to environment variables
type AzureKeyVaultKeyHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureKeyVaultMultiValueSecretHandler handles getting and formatting Azure Key Vault Secret containing multiple values from Azure Key Vault to Kubernetes
type AzureKeyVaultMultiValueSecretHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// NewAzureKeyVaultSecretHandler return a new AzureKeyVaultSecretHandler
func NewAzureKeyVaultSecretHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureKeyVaultSecretHandler {
	return &AzureKeyVaultSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureKeyVaultCertificateHandler return a new AzureKeyVaultCertificateHandler
func NewAzureKeyVaultCertificateHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureKeyVaultCertificateHandler {
	return &AzureKeyVaultCertificateHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureKeyVaultKeyHandler returns a new AzureKeyVaultKeyHandler
func NewAzureKeyVaultKeyHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureKeyVaultKeyHandler {
	return &AzureKeyVaultKeyHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureKeyVaultMultiKeySecretHandler returns a new AzureKeyVaultMultiKeySecretHandler
func NewAzureKeyVaultMultiKeySecretHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureKeyVaultMultiValueSecretHandler {
	return &AzureKeyVaultMultiValueSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// Handle getting and formating Azure Key Vault Secret from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultSecretHandler) Handle() (map[string]string, error) {
	if h.secretSpec.Spec.Vault.Object.Type == akvsv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret && h.secretSpec.Spec.Output.Secret.DataKey != "" {
		log.Warnf("output data key for %s/%s ignored, since vault object type is '%s' it will use its own keys", h.secretSpec.Namespace, h.secretSpec.Name, akvsv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret)
	}

	values := make(map[string]string)

	fmt.Fprintln(os.Stdout, "Getting secret now!")
	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		fmt.Fprintln(os.Stdout, "Found error getting secret now!")
		return nil, err
	}

	switch h.secretSpec.Spec.Output.Secret.Type {
	case corev1.SecretTypeBasicAuth:
		creds := strings.Split(secret, ":")
		if len(creds) != 2 {
			return nil, fmt.Errorf("unable to handle azure key vault secret as basic auth - check that formatting is correct 'username:password'")
		}
		values[corev1.BasicAuthUsernameKey] = creds[0]
		values[corev1.BasicAuthPasswordKey] = creds[1]

	case corev1.SecretTypeDockerConfigJson:
		values[corev1.DockerConfigJsonKey] = secret

	case corev1.SecretTypeDockercfg:
		values[corev1.DockerConfigKey] = secret

	case corev1.SecretTypeSSHAuth:
		values[corev1.SSHAuthPrivateKey] = secret

	default:
		if h.secretSpec.Spec.Vault.Object.Type != akvsv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret &&
			h.secretSpec.Spec.Output.Secret.DataKey == "" {
			return nil, fmt.Errorf("no datakey spesified for output secret")
		}
		values[h.secretSpec.Spec.Output.Secret.DataKey] = secret
	}

	return values, nil
}

// Handle getting and formating Azure Key Vault Certificate from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultCertificateHandler) Handle() (map[string]string, error) {
	values := make(map[string]string)
	var err error

	exportPrivateKey := h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeTLS
	if !exportPrivateKey && h.secretSpec.Spec.Output.Secret.DataKey == "" {
		return nil, fmt.Errorf("no datakey spesified for output secret")
	}

	cert, err := h.vaultService.GetCertificate(&h.secretSpec.Spec.Vault, exportPrivateKey)

	var pubKey []byte
	var privKey []byte

	if err != nil {
		return nil, err
	}
	if exportPrivateKey {
		if pubKey, err = cert.ExportPublicKeyAsPem(); err != nil {
			return nil, err
		}
		if privKey, err = cert.ExportPrivateKeyAsPem(); err != nil {
			return nil, err
		}

		values[corev1.TLSCertKey] = string(pubKey)
		values[corev1.TLSPrivateKeyKey] = string(privKey)
	} else {
		if pubKey, err = cert.ExportPublicKeyAsPem(); err != nil {
			return nil, err
		}
		values[h.secretSpec.Spec.Output.Secret.DataKey] = string(pubKey)
	}

	return values, nil
}

// Handle getting and formating Azure Key Vault Key from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultKeyHandler) Handle() (map[string]string, error) {
	key, err := h.vaultService.GetKey(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	values[h.secretSpec.Spec.Output.Secret.DataKey] = key
	return values, nil
}

// Handle getting and formating Azure Key Vault Secret containing mulitple values from Azure Key Vault to Kubernetes
func (h *AzureKeyVaultMultiValueSecretHandler) Handle() (map[string]string, error) {
	values := make(map[string]string)

	if h.secretSpec.Spec.Vault.Object.ContentType == "" {
		return nil, fmt.Errorf("cannot use '%s' without also specifying content type", azureKeyVaultSecretv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret)
	}

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	var dat map[string]string

	switch h.secretSpec.Spec.Vault.Object.ContentType {
	case akvsv1alpha1.AzureKeyVaultObjectContentTypeJSON:
		if err := json.Unmarshal([]byte(secret), &dat); err != nil {
			return nil, err
		}
	case akvsv1alpha1.AzureKeyVaultObjectContentTypeYaml:
		if err := yaml.Unmarshal([]byte(secret), &dat); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("content type '%s' not supported", h.secretSpec.Spec.Vault.Object.ContentType)
	}

	for k, v := range dat {
		values[k] = v
	}

	return values, nil
}
