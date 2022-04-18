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

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// KubernetesSecretHandler handles getting and formatting secrets from Azure Key Vault to Kubernetes
type KubernetesHandler interface {
	HandleSecret() (map[string][]byte, error)
	HandleConfigMap() (map[string]string, error)
}

// azureSecretHandler handles getting and formatting Azure Key Vault Secret from Azure Key Vault to Kubernetes
type azureSecretHandler struct {
	secretSpec    *akv.AzureKeyVaultSecret
	vaultService  vault.Service
	transformator transformers.Transformator
}

// azureCertificateHandler handles getting and formatting Azure Key Vault Certificate from Azure Key Vault to Kubernetes
type azureCertificateHandler struct {
	secretSpec   *akv.AzureKeyVaultSecret
	vaultService vault.Service
}

// azureKeyHandler handles getting and formatting Azure Key Vault Key from Azure Key Vault to Kubernetes
type azureKeyHandler struct {
	secretSpec   *akv.AzureKeyVaultSecret
	vaultService vault.Service
}

// azureMultiValueSecretHandler handles getting and formatting Azure Key Vault Secret containing multiple values from Azure Key Vault to Kubernetes
type azureMultiValueSecretHandler struct {
	secretSpec   *akv.AzureKeyVaultSecret
	vaultService vault.Service
}

// NewAzureSecretHandler return a new AzureSecretHandler
func NewAzureSecretHandler(secretSpec *akv.AzureKeyVaultSecret, vaultService vault.Service, transformator transformers.Transformator) *azureSecretHandler {
	return &azureSecretHandler{
		secretSpec:    secretSpec,
		vaultService:  vaultService,
		transformator: transformator,
	}
}

// NewAzureCertificateHandler return a new AzureCertificateHandler
func NewAzureCertificateHandler(secretSpec *akv.AzureKeyVaultSecret, vaultService vault.Service) *azureCertificateHandler {
	return &azureCertificateHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureKeyHandler returns a new AzureKeyHandler
func NewAzureKeyHandler(secretSpec *akv.AzureKeyVaultSecret, vaultService vault.Service) *azureKeyHandler {
	return &azureKeyHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// NewAzureMultiKeySecretHandler returns a new AzureMultiKeySecretHandler
func NewAzureMultiKeySecretHandler(secretSpec *akv.AzureKeyVaultSecret, vaultService vault.Service) *azureMultiValueSecretHandler {
	return &azureMultiValueSecretHandler{
		secretSpec:   secretSpec,
		vaultService: vaultService,
	}
}

// Handle getting and formating Azure Key Vault Secret from Azure Key Vault to Kubernetes
func (h *azureSecretHandler) HandleSecret() (map[string][]byte, error) {
	if h.secretSpec.Spec.Vault.Object.Type == akv.AzureKeyVaultObjectTypeMultiKeyValueSecret && h.secretSpec.Spec.Output.Secret.DataKey != "" {
		klog.InfoS("output data key ignored - vault object type is multi key and will use its own keys", klog.KObj(h.secretSpec))
	}

	values := make(map[string][]byte)

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	secret, err = h.transformator.Transform(secret)
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

	case corev1.SecretTypeTLS:
		pfxRaw, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode base64 encoded secret, error: %+v", err)
		}
		cert, err := vault.NewCertificateFromPfx(pfxRaw, h.secretSpec.Spec.Output.Secret.ChainOrder == "ensureserverfirst")
		if err != nil {
			return nil, fmt.Errorf("Error while processing secret content as pfx, error: %+v", err)
		}
		if values[corev1.TLSCertKey], err = cert.ExportPublicKeyAsPem(); err != nil {
			return nil, fmt.Errorf("Error exporting public key, error: %+v", err)
		}
		if values[corev1.TLSPrivateKeyKey], err = cert.ExportPrivateKeyAsPem(); err != nil {
			return nil, fmt.Errorf("Error exporting private key, error: %+v", err)
		}

	default:
		if h.secretSpec.Spec.Vault.Object.Type != akv.AzureKeyVaultObjectTypeMultiKeyValueSecret &&
			h.secretSpec.Spec.Output.Secret.DataKey == "" {
			return nil, fmt.Errorf("no datakey spesified for output secret")
		}
		values[h.secretSpec.Spec.Output.Secret.DataKey] = []byte(secret)
	}

	return values, nil
}

// Handle getting and formating Azure Key Vault Secret from Azure Key Vault to Kubernetes
func (h *azureSecretHandler) HandleConfigMap() (map[string]string, error) {
	if h.secretSpec.Spec.Vault.Object.Type == akv.AzureKeyVaultObjectTypeMultiKeyValueSecret && h.secretSpec.Spec.Output.ConfigMap.DataKey != "" {
		klog.InfoS("output data key ignored - vault object type is multi key and will use its own keys", klog.KObj(h.secretSpec))
	}

	values := make(map[string]string)

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	secret, err = h.transformator.Transform(secret)
	if err != nil {
		return nil, err
	}

	if h.secretSpec.Spec.Vault.Object.Type != akv.AzureKeyVaultObjectTypeMultiKeyValueSecret &&
		h.secretSpec.Spec.Output.ConfigMap.DataKey == "" {
		return nil, fmt.Errorf("no datakey spesified for output configmap")
	}
	values[h.secretSpec.Spec.Output.ConfigMap.DataKey] = secret

	return values, nil
}

// Handle getting and formating Azure Key Vault Certificate from Azure Key Vault to Kubernetes
func (h *azureCertificateHandler) HandleSecret() (map[string][]byte, error) {
	values := make(map[string][]byte)
	var err error
	options := vault.CertificateOptions{
		ExportPrivateKey:  h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeTLS || h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeOpaque,
		EnsureServerFirst: h.secretSpec.Spec.Output.Secret.ChainOrder == "ensureserverfirst",
	}

	if !options.ExportPrivateKey && h.secretSpec.Spec.Output.Secret.DataKey == "" {
		return nil, fmt.Errorf("no datakey specified for output secret")
	}

	cert, err := h.vaultService.GetCertificate(&h.secretSpec.Spec.Vault, &options)
	if err != nil {
		return nil, err
	}

	if h.secretSpec.Spec.Output.Secret.Type == corev1.SecretTypeOpaque {
		values[h.secretSpec.Spec.Output.Secret.DataKey] = cert.ExportRaw()
	} else if options.ExportPrivateKey {
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

// Handle getting and formating Azure Key Vault Certificate from Azure Key Vault to Kubernetes
func (h *azureCertificateHandler) HandleConfigMap() (map[string]string, error) {
	values := make(map[string]string)
	var err error

	cert, err := h.vaultService.GetCertificate(&h.secretSpec.Spec.Vault, nil)
	if err != nil {
		return nil, err
	}

	value, err := cert.ExportPublicKeyAsPem()
	if err != nil {
		return nil, err
	}

	values[h.secretSpec.Spec.Output.ConfigMap.DataKey] = string(value)

	return values, nil
}

// Handle getting and formating Azure Key Vault Key from Azure Key Vault to Kubernetes
func (h *azureKeyHandler) HandleSecret() (map[string][]byte, error) {
	key, err := h.vaultService.GetKey(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	values := make(map[string][]byte)
	values[h.secretSpec.Spec.Output.Secret.DataKey] = []byte(key)
	return values, nil
}

// Handle getting and formating Azure Key Vault Key from Azure Key Vault to Kubernetes
func (h *azureKeyHandler) HandleConfigMap() (map[string]string, error) {
	key, err := h.vaultService.GetKey(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	values[h.secretSpec.Spec.Output.ConfigMap.DataKey] = key
	return values, nil
}

// Handle getting and formating Azure Key Vault Secret containing multiple values from Azure Key Vault to Kubernetes
func (h *azureMultiValueSecretHandler) HandleSecret() (map[string][]byte, error) {
	values := make(map[string][]byte)

	if h.secretSpec.Spec.Vault.Object.ContentType == "" {
		return nil, fmt.Errorf("cannot use '%s' without also specifying content type", akv.AzureKeyVaultObjectTypeMultiKeyValueSecret)
	}

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	var dat map[string]string

	switch h.secretSpec.Spec.Vault.Object.ContentType {
	case akv.AzureKeyVaultObjectContentTypeJSON:
		if err := json.Unmarshal([]byte(secret), &dat); err != nil {
			return nil, err
		}
	case akv.AzureKeyVaultObjectContentTypeYaml:
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

// Handle getting and formating Azure Key Vault Secret containing multiple values from Azure Key Vault to Kubernetes
func (h *azureMultiValueSecretHandler) HandleConfigMap() (map[string]string, error) {
	values := make(map[string]string)

	if h.secretSpec.Spec.Vault.Object.ContentType == "" {
		return nil, fmt.Errorf("cannot use '%s' without also specifying content type", akv.AzureKeyVaultObjectTypeMultiKeyValueSecret)
	}

	secret, err := h.vaultService.GetSecret(&h.secretSpec.Spec.Vault)
	if err != nil {
		return nil, err
	}

	var dat map[string]string

	switch h.secretSpec.Spec.Vault.Object.ContentType {
	case akv.AzureKeyVaultObjectContentTypeJSON:
		if err := json.Unmarshal([]byte(secret), &dat); err != nil {
			return nil, err
		}
	case akv.AzureKeyVaultObjectContentTypeYaml:
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
