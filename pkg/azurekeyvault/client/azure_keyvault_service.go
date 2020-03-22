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

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	akvs "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1"
)

const (
	certificateTypePem string = "application/x-pem-file"
	certificateTypePfx        = "application/x-pkcs12"
)

// Service is an interface for implementing vaults
type Service interface {
	GetSecret(secret *akvs.AzureKeyVault) (string, error)
	GetKey(secret *akvs.AzureKeyVault) (string, error)
	GetCertificate(secret *akvs.AzureKeyVault, exportPrivateKey bool) (*Certificate, error)
}

type azureKeyVaultService struct {
	credentials AzureKeyVaultCredentials
}

// NewService creates a new AzureKeyVaultService
func NewService(credentials AzureKeyVaultCredentials) Service {
	return &azureKeyVaultService{
		credentials: credentials,
	}
}

// GetSecret download secrets from Azure Key Vault
func (a *azureKeyVaultService) GetSecret(vaultSpec *akvs.AzureKeyVault) (string, error) {
	if vaultSpec.Object.Name == "" {
		return "", fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	//Get secret value from Azure Key Vault
	vaultClient, err := a.getClient()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseURL := a.credentials.Endpoint(vaultSpec.Name)
	secretBundle, err := vaultClient.GetSecret(ctx, baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)

	if err != nil {
		return "", err
	}
	return *secretBundle.Value, nil
}

// GetKey download encryption keys from Azure Key Vault
func (a *azureKeyVaultService) GetKey(vaultSpec *akvs.AzureKeyVault) (string, error) {
	if vaultSpec.Object.Name == "" {
		return "", fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	vaultClient, err := a.getClient()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseURL := a.credentials.Endpoint(vaultSpec.Name)
	keyBundle, err := vaultClient.GetKey(ctx, baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)

	if err != nil {
		return "", err
	}

	return *keyBundle.Key.N, nil
}

// GetCertificate download public/private certificates from Azure Key Vault
func (a *azureKeyVaultService) GetCertificate(vaultSpec *akvs.AzureKeyVault, exportPrivateKey bool) (*Certificate, error) {
	vaultClient, err := a.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseURL := a.credentials.Endpoint(vaultSpec.Name)

	certBundle, err := vaultClient.GetCertificate(ctx, baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from azure key vault, error: %+v", err)
	}

	if exportPrivateKey {
		if !*certBundle.Policy.KeyProperties.Exportable {
			return nil, fmt.Errorf("cannot export private key because key is not exportable in azure key vault")
		}
		secretBundle, err := vaultClient.GetSecret(ctx, baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)
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
			return NewCertificateFromPfx(pfxRaw)
		default:
			return nil, fmt.Errorf("failed to get certificate from azure key vault - unknown content type '%s'", *secretBundle.ContentType)
		}
	}

	return NewCertificateFromDer(*certBundle.Cer)
}

func (a *azureKeyVaultService) getClient() (*keyvault.BaseClient, error) {
	authorizer, err := a.credentials.Authorizer()
	if err != nil {
		return nil, err
	}

	keyClient := keyvault.New()
	keyClient.Client.PollingDelay = 5 * time.Second
	keyClient.Client.PollingDuration = 20 * time.Second
	keyClient.Client.RetryAttempts = 2
	keyClient.Client.RetryDuration = 5 * time.Second
	keyClient.Authorizer = authorizer

	return &keyClient, nil
}
