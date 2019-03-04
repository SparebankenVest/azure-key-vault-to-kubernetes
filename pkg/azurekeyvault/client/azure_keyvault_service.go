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

	"github.com/Azure/go-autorest/autorest"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	akvsv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
)

const (
	certificateTypePem string = "application/x-pem-file"
	certificateTypePfx        = "application/x-pkcs12"
)

// ServiceCredentials for service principal
type ServiceCredentials struct {
	ClientID     string
	ClientSecret string
	TenantID     string
}

// Service is an interface for implementing vaults
type Service interface {
	GetSecret(secret *akvsv1alpha1.AzureKeyVault) (string, error)
	GetKey(secret *akvsv1alpha1.AzureKeyVault) (string, error)
	GetCertificate(secret *akvsv1alpha1.AzureKeyVault, exportPrivateKey bool) (*Certificate, error)
}

type azureKeyVaultService struct {
	credentials *ServiceCredentials
}

// NewService creates a new AzureKeyVaultService using built in Managed Service Identity for authentication
func NewService() Service {
	return &azureKeyVaultService{}
}

// NewServiceWithClientCredentials creates a new AzureKeyVaultService using service principal provided
func NewServiceWithClientCredentials(credentials *ServiceCredentials) Service {
	return &azureKeyVaultService{
		credentials: credentials,
	}
}

// GetSecret download secrets from Azure Key Vault
func (a *azureKeyVaultService) GetSecret(vaultSpec *akvsv1alpha1.AzureKeyVault) (string, error) {
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
func (a *azureKeyVaultService) GetKey(vaultSpec *akvsv1alpha1.AzureKeyVault) (string, error) {
	if vaultSpec.Object.Name == "" {
		return "", fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", vaultSpec.Name)
	keyBundle, err := vaultClient.GetKey(context.Background(), baseURL, vaultSpec.Object.Name, vaultSpec.Object.Version)

	if err != nil {
		return "", err
	}

	return *keyBundle.Key.N, nil
}

// GetCertificate download public/private certificates from Azure Key Vault
func (a *azureKeyVaultService) GetCertificate(vaultSpec *akvsv1alpha1.AzureKeyVault, exportPrivateKey bool) (*Certificate, error) {
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

func (a *azureKeyVaultService) getClient(resource string) (*keyvault.BaseClient, error) {
	var authorizer autorest.Authorizer
	var err error

	if a.credentials != nil {
		cred := auth.NewClientCredentialsConfig(a.credentials.ClientID, a.credentials.ClientSecret, a.credentials.TenantID)
		cred.Resource = resource // resource must be Azure Key Vault resource

		if authorizer, err = cred.Authorizer(); err != nil {
			return nil, fmt.Errorf("failed to create authorizer based on service principal credentials, err: %+v", err)
		}
	} else {
		if authorizer, err = auth.NewAuthorizerFromEnvironmentWithResource(resource); err != nil {
			return nil, fmt.Errorf("failed to create authorizer from environment, err: %+v", err)
		}
	}

	keyClient := keyvault.New()
	keyClient.Authorizer = authorizer

	return &keyClient, nil
}
