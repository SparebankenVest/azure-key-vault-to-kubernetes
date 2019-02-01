package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
)

// AzureKeyVaultService provide interaction with Azure Key Vault
type AzureKeyVaultService struct {
}

// NewAzureKeyVaultService creates a new AzureKeyVaultService using built in Managed Service Identity for authentication
func NewAzureKeyVaultService() *AzureKeyVaultService {
	return &AzureKeyVaultService{}
}

// GetSecret returns a secret from Azure Key Vault
func (a *AzureKeyVaultService) GetSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
	//Get secret value from Azure Key Vault
	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	var vaultSecret string

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)

	switch strings.ToLower(secret.Spec.Vault.ObjectType) {
	case "certificate":
		secretBundle, err := vaultClient.GetCertificate(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

		if err != nil {
			return "", err
		}
		vaultSecret = string(*secretBundle.Cer)
		decSecret, err := base64.StdEncoding.DecodeString(vaultSecret)
		if err != nil {
			return "", fmt.Errorf("failed to base64 decode Azure Key Vault certificate for %s / %s, error: %+v", secret.Namespace, secret.Name, err)
		}
		vaultSecret = string(decSecret)
	default:
		secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

		if err != nil {
			return "", err
		}
		vaultSecret = *secretBundle.Value
	}

	return vaultSecret, nil
}

// GetCertificate returns a certificate from Azure Key Vault
func (a *AzureKeyVaultService) getCertificate(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
	//Get secret value from Azure Key Vault
	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
	certBundle, err := vaultClient.GetCertificate(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

	if err != nil {
		return "", err
	}

	return string(*certBundle.Cer), nil
}

// // GetSecret returns a secret from Azure Key Vault
// func (a *AzureKeyVaultService) GetKey(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
// 	//Get secret value from Azure Key Vault
// 	vaultClient, err := a.getClient("https://vault.azure.net")
// 	if err != nil {
// 		return "", err
// 	}
//
// 	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
// 	secretPack, err := vaultClient.GetKey(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")
//
// 	if err != nil {
// 		return "", err
// 	}
// 	return *secretPack.Value, nil
// }

func (a *AzureKeyVaultService) getClient(resource string) (*keyvault.BaseClient, error) {
	authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(resource)
	if err != nil {
		return nil, err
	}

	keyClient := keyvault.New()
	keyClient.Authorizer = authorizer

	return &keyClient, nil
}
