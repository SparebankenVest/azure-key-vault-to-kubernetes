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

package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	akvsv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
)

// KubernetesSecretHandler handles getting and formatting secrets from Azure Key Vault to Kubernetes
type KubernetesSecretHandler interface {
	Handle() (map[string][]byte, error)
}

// AzureSecretHandler handles getting and formatting Azure Key Vault Secret from Azure Key Vault to Kubernetes
type AzureSecretHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureBase64EncodedSecretHandler handles getting and decoding Azure Key Vault Secret from Azure Key Vault to Kubernetes
type AzureBase64EncodedSecretHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureCertificateHandler handles getting and formatting Azure Key Vault Certificate from Azure Key Vault to Kubernetes
type AzureCertificateHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureKeyHandler handles getting and formatting Azure Key Vault Key from Azure Key Vault to Kubernetes
type AzureKeyHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// AzureMultiValueSecretHandler handles getting and formatting Azure Key Vault Secret containing multiple values from Azure Key Vault to Kubernetes
type AzureMultiValueSecretHandler struct {
	secretSpec   *akvsv1alpha1.AzureKeyVaultSecret
	vaultService vault.Service
}

// NewAzureSecretHandler return a new AzureSecretHandler
func NewAzureSecretHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureSecretHandler {
	return &AzureSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureBase64EncodedSecretHandler return a new AzureBase64EncodedSecretHandler
func NewAzureBase64EncodedSecretHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureBase64EncodedSecretHandler {
	return &AzureBase64EncodedSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureCertificateHandler return a new AzureCertificateHandler
func NewAzureCertificateHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureCertificateHandler {
	return &AzureCertificateHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureKeyHandler returns a new AzureKeyHandler
func NewAzureKeyHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureKeyHandler {
	return &AzureKeyHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureMultiKeySecretHandler returns a new AzureMultiKeySecretHandler
func NewAzureMultiKeySecretHandler(secretSpec *akvsv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) *AzureMultiValueSecretHandler {
	return &AzureMultiValueSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// Handle getting and formating Azure Key Vault Secret from Azure Key Vault to Kubernetes
func (h *AzureSecretHandler) Handle() (map[string][]byte, error) {
	if h.secretSpec.Spec.Vault.Object.Type == akvsv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret && h.secretSpec.Spec.Output.Secret.DataKey != "" {
		log.Warnf("output data key for %s/%s ignored, since vault object type is '%s' it will use its own keys", h.secretSpec.Namespace, h.secretSpec.Name, akvsv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret)
	}

	values := make(map[string][]byte)

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	switch h.secretSpec.Spec.Output.Secret.Type {
	case corev1.SecretTypeBasicAuth:
		creds := strings.Split(secret, ":")
		if len(creds) != 2 {
			return nil, fmt.Errorf("unable to handle azure key vault secret as basic auth - check that formatting is correct 'username:password'")
		}
		values[corev1.BasicAuthUsernameKey] = []byte(creds[0])
		values[corev1.BasicAuthPasswordKey] = []byte(creds[1])

	case corev1.SecretTypeDockerConfigJson:
		values[corev1.DockerConfigJsonKey] = []byte(secret)

	case corev1.SecretTypeDockercfg:
		values[corev1.DockerConfigKey] = []byte(secret)

	case corev1.SecretTypeSSHAuth:
		values[corev1.SSHAuthPrivateKey] = []byte(secret)

	default:
		if h.secretSpec.Spec.Vault.Object.Type != akvsv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret &&
			h.secretSpec.Spec.Output.Secret.DataKey == "" {
			return nil, fmt.Errorf("no datakey spesified for output secret")
		}
		values[h.secretSpec.Spec.Output.Secret.DataKey] = []byte(secret)
	}

	return values, nil
}

// Handle getting and decoding base64 Azure Key Vault Secret from Azure Key Vault to Kubernetes
func (h *AzureBase64EncodedSecretHandler) Handle() (map[string][]byte, error) {
	if h.secretSpec.Spec.Output.Secret.DataKey == "" {
		return nil, fmt.Errorf("no datakey spesified for output secret")
	}

	var err error

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	decodedData, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	values := make(map[string][]byte)
	values[h.secretSpec.Spec.Output.Secret.DataKey] = decodedData
	return values, nil
}

// Handle getting and formating Azure Key Vault Certificate from Azure Key Vault to Kubernetes
func (h *AzureCertificateHandler) Handle() (map[string][]byte, error) {
	values := make(map[string][]byte)
	var err error

	exportPrivateKey := h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeTLS || h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeOpaque
	if !exportPrivateKey && h.secretSpec.Spec.Output.Secret.DataKey == "" {
		return nil, fmt.Errorf("no datakey spesified for output secret")
	}

	log.Infof("Exporting certificate with private key: %t", exportPrivateKey)

	cert, err := h.vaultService.GetCertificate(&h.secretSpec.Spec.Vault, exportPrivateKey)
	if err != nil {
		return nil, err
	}

	if h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeOpaque {
		values[h.secretSpec.Spec.Output.Secret.DataKey] = cert.ExportRaw()
	} else if exportPrivateKey {
		if values[corev1.TLSCertKey], err = cert.ExportPublicKeyAsPem(); err != nil {
			return nil, err
		}
		if values[corev1.TLSPrivateKeyKey], err = cert.ExportPrivateKeyAsPem(); err != nil {
			return nil, err
		}
	} else {
		values[h.secretSpec.Spec.Output.Secret.DataKey], err = cert.ExportPublicKeyAsPem()
		if err != nil {
			return nil, err
		}
	}

	return values, nil
}

// Handle getting and formating Azure Key Vault Key from Azure Key Vault to Kubernetes
func (h *AzureKeyHandler) Handle() (map[string][]byte, error) {
	key, err := h.vaultService.GetKey(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	values := make(map[string][]byte)
	values[h.secretSpec.Spec.Output.Secret.DataKey] = []byte(key)
	return values, nil
}

// Handle getting and formating Azure Key Vault Secret containing mulitple values from Azure Key Vault to Kubernetes
func (h *AzureMultiValueSecretHandler) Handle() (map[string][]byte, error) {
	values := make(map[string][]byte)

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
		values[k] = []byte(v)
	}

	return values, nil
}
