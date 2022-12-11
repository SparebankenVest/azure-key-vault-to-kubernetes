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

package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
	akvs "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
)

const (
	certificateTypePem string = "application/x-pem-file"
	certificateTypePfx string = "application/x-pkcs12"
)

// Service is an interface for implementing vaults
type Service interface {
	GetSecret(secret *akvs.AzureKeyVault) (string, error)
	GetKey(secret *akvs.AzureKeyVault) (string, error)
	GetCertificate(secret *akvs.AzureKeyVault, options *CertificateOptions) (*Certificate, error)
}

// CertificateOptions has options for exporting certificate
type CertificateOptions struct {
	ExportPrivateKey  bool
	EnsureServerFirst bool
}

type azureKeyVaultService struct {
	credentials azure.LegacyTokenCredential
}

// NewService creates a new AzureKeyVaultService
func NewService(creds azure.LegacyTokenCredential) Service {
	return &azureKeyVaultService{
		credentials: creds,
	}
}

func vaultNameToURL(name string) string {
	return fmt.Sprintf("https://%s.vault.azure.net", name)
}

// GetSecret download secrets from Azure Key Vault
func (a *azureKeyVaultService) GetSecret(vaultSpec *akvs.AzureKeyVault) (string, error) {
	if vaultSpec.Object.Name == "" {
		return "", fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	client, err := azsecrets.NewClient(vaultNameToURL(vaultSpec.Name), a.credentials, nil)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.GetSecret(ctx, vaultSpec.Object.Name, vaultSpec.Object.Version, &azsecrets.GetSecretOptions{})

	if err != nil {
		return "", err
	}
	return *response.Value, nil
}

// GetKey download encryption keys from Azure Key Vault
func (a *azureKeyVaultService) GetKey(vaultSpec *akvs.AzureKeyVault) (string, error) {
	if vaultSpec.Object.Name == "" {
		return "", fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	client, err := azkeys.NewClient(vaultNameToURL(vaultSpec.Name), a.credentials, nil)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := client.GetKey(ctx, vaultSpec.Object.Name, vaultSpec.Object.Version, &azkeys.GetKeyOptions{})

	if err != nil {
		return "", err
	}
	data := &response.Key.N

	return string(*data), nil
}

// GetCertificate download public/private certificates from Azure Key Vault
func (a *azureKeyVaultService) GetCertificate(vaultSpec *akvs.AzureKeyVault, options *CertificateOptions) (*Certificate, error) {
	client, err := azcertificates.NewClient(vaultNameToURL(vaultSpec.Name), a.credentials, &azcertificates.ClientOptions{})
	if err != nil {
		return nil, err
	}
	clientSecret, err := azsecrets.NewClient(vaultNameToURL(vaultSpec.Name), a.credentials, &azsecrets.ClientOptions{})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.GetCertificate(ctx, vaultSpec.Object.Name, vaultSpec.Object.Version, &azcertificates.GetCertificateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from azure key vault, error: %+v", err)
	}

	if options.ExportPrivateKey {
		if !*response.Policy.KeyProperties.Exportable {
			return nil, fmt.Errorf("cannot export private key because key is not exportable in azure key vault")
		}
		secretBundle, err := clientSecret.GetSecret(ctx, vaultSpec.Object.Name, vaultSpec.Object.Version, &azsecrets.GetSecretOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get private certificate from azure key vault, error: %+v", err)
		}

		switch *secretBundle.ContentType {
		case certificateTypePem:
			return NewCertificateFromPem(*secretBundle.Value)
		case certificateTypePfx:
			pfxRaw, err := base64.StdEncoding.DecodeString(*secretBundle.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 encoded pfx, error: %+v", err)
			}
			if options.EnsureServerFirst {
				return NewCertificateFromPfx(pfxRaw, true)
			}
			return NewCertificateFromPfx(pfxRaw, false)
		default:
			return nil, fmt.Errorf("failed to get certificate from azure key vault - unknown content type '%s'", *secretBundle.ContentType)
		}
	}

	return NewCertificateFromDer(response.CER)
}
