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

package vault

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
)

const (
	azureKeyVaultCertificateTypePem string = "application/x-pem-file"
	azureKeyVaultCertificateTypePfx        = "application/x-pkcs12"
)

// Service is an interface for implementing vaults
type Service interface {
	// GetObject(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (map[string][]byte, error)
	GetSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVault) (string, error)
	GetKey(secret *azureKeyVaultSecretv1alpha1.AzureKeyVault) (*[]byte, error)
	GetCertificate(secret *azureKeyVaultSecretv1alpha1.AzureKeyVault, exportPrivateKey bool) (*AzureKeyVaultCertificate, error)
}

type azureKeyVaultService struct {
}

// NewService creates a new AzureKeyVaultService using built in Managed Service Identity for authentication
func NewService() Service {
	return &azureKeyVaultService{}
}

// GetSecret download secrets from Azure Key Vault
func (a *azureKeyVaultService) GetSecret(vaultSpec *azureKeyVaultSecretv1alpha1.AzureKeyVault) (string, error) {
	if vaultSpec.Object.Name == "" {
		return "", fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	//Get secret value from Azure Key Vault
	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", vaultSpec.Name)
	secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)

	if err != nil {
		return "", err
	}
	return *secretBundle.Value, nil
}

// GetKey download encryption keys from Azure Key Vault
func (a *azureKeyVaultService) GetKey(vaultSpec *azureKeyVaultSecretv1alpha1.AzureKeyVault) (*[]byte, error) {
	if vaultSpec.Object.Name == "" {
		return nil, fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return nil, err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", vaultSpec.Name)
	keyBundle, err := vaultClient.GetKey(context.Background(), baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)

	if err != nil {
		return nil, err
	}

	keyRaw, err := base64.StdEncoding.DecodeString(*keyBundle.Key.N)
	if err != nil {
		return nil, err
	}

	return &keyRaw, nil
}

// GetCertificate download public/private certificates from Azure Key Vault
func (a *azureKeyVaultService) GetCertificate(vaultSpec *azureKeyVaultSecretv1alpha1.AzureKeyVault, exportPrivateKey bool) (*AzureKeyVaultCertificate, error) {
	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return nil, err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", vaultSpec.Name)

	certBundle, err := vaultClient.GetCertificate(context.Background(), baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from azure key vault, error: %+v", err)
	}

	if exportPrivateKey {
		if !*certBundle.Policy.KeyProperties.Exportable {
			return nil, fmt.Errorf("cannot export private key because key is not exportable in azure key vault")
		}
		secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to get private certificate from azure key vault, error: %+v", err)
		}

		switch *secretBundle.ContentType {
		case azureKeyVaultCertificateTypePem:
			return NewAzureKeyVaultCertificateFromPem(*secretBundle.Value)
		case azureKeyVaultCertificateTypePfx:
			pfxRaw, err := base64.StdEncoding.DecodeString(*secretBundle.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 encoded pfx, error: %+v", err)
			}
			return NewAzureKeyVaultCertificateFromPfx(pfxRaw)
		default:
			return nil, fmt.Errorf("failed to get certificate from azure key vault - unknown content type '%s'", *secretBundle.ContentType)
		}
	}

	return NewAzureKeyVaultCertificateFromDer(*certBundle.Cer)
}

func (a *azureKeyVaultService) getClient(resource string) (*keyvault.BaseClient, error) {
	authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(resource)
	if err != nil {
		return nil, err
	}

	keyClient := keyvault.New()
	keyClient.Authorizer = authorizer

	return &keyClient, nil
}
