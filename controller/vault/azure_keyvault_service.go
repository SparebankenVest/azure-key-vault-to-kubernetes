package vault

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
)

// AzureKeyVaultObjectType defines which Object type to get from Azure Key Vault
type AzureKeyVaultObjectType string

const (
	// AzureKeyVaultObjectTypeSecret - get Secret object type from Azure Key Vault
	AzureKeyVaultObjectTypeSecret AzureKeyVaultObjectType = "secret"
	// AzureKeyVaultObjectTypeCertificate - get Certificate object type from Azure Key Vault
	AzureKeyVaultObjectTypeCertificate = "certificate"
	// AzureKeyVaultObjectTypeKey - get Key object type from Azure Key Vault
	AzureKeyVaultObjectTypeKey = "key"
	// AzureKeyVaultObjectTypeStorage - get Storeage object type from Azure Key Vault
	AzureKeyVaultObjectTypeStorage = "storage"
)

// AzureKeyVaultService provide interaction with Azure Key Vault
type AzureKeyVaultService struct {
}

// NewAzureKeyVaultService creates a new AzureKeyVaultService using built in Managed Service Identity for authentication
func NewAzureKeyVaultService() *AzureKeyVaultService {
	return &AzureKeyVaultService{}
}

// GetSecret returns a secret from Azure Key Vault
func (a *AzureKeyVaultService) GetSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (map[string][]byte, error) {
	switch secret.Spec.Vault.ObjectType {
	case AzureKeyVaultObjectTypeCertificate:
		return getCertificate(secret)
	default:
		return getSecret(secret)
	}
}

func getSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (map[string][]byte, error) {
	var secretValue map[string][]byte

	//Get secret value from Azure Key Vault
	vaultClient, err := getClient("https://vault.azure.net")
	if err != nil {
		return secretValue, err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
	secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

	if err != nil {
		return secretValue, err
	}

	value := make([]byte, 0)
	base64.RawStdEncoding.Encode(value, []byte(*secretBundle.Value))

	secretValue[secret.Spec.OutputSecret.KeyName] = value
	return secretValue, nil
}

// getCertificate return public/private certificate pems
func getCertificate(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (map[string][]byte, error) {
	var secretValue map[string][]byte

	//Get secret value from Azure Key Vault
	vaultClient, err := getClient("https://vault.azure.net")
	if err != nil {
		return secretValue, err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)

	secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

	if err != nil {
		return secretValue, fmt.Errorf("failed to get secret from azure key vault, error: %+v", err)
	}

	privateDer, rest := pem.Decode([]byte(*secretBundle.Value))
	publicDer, _ := pem.Decode(rest)

	privateKey := make([]byte, 0)
	publicCrt := make([]byte, 0)

	base64.RawStdEncoding.Encode(privateKey, pem.EncodeToMemory(privateDer))
	base64.RawStdEncoding.Encode(publicCrt, pem.EncodeToMemory(publicDer))

	secretValue["tls.key"] = privateKey
	secretValue["tls.crt"] = publicCrt
	return secretValue, nil
}

func getClient(resource string) (*keyvault.BaseClient, error) {
	authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(resource)
	if err != nil {
		return nil, err
	}

	keyClient := keyvault.New()
	keyClient.Authorizer = authorizer

	return &keyClient, nil
}

// // GetCertificate returns a certificate from Azure Key Vault
// func (a *AzureKeyVaultService) getCertificate(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
// 	//Get secret value from Azure Key Vault
// 	vaultClient, err := a.getClient("https://vault.azure.net")
// 	if err != nil {
// 		return "", err
// 	}
//
// 	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
// 	certBundle, err := vaultClient.GetCertificate(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")
//
// 	if err != nil {
// 		return "", err
// 	}
//
// 	return string(*certBundle.Cer), nil
// }

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

// func decodePem(certInput string) tls.Certificate {
// 	var cert tls.Certificate
// 	certPEMBlock := []byte(certInput)
// 	var certDERBlock *pem.Block
// 	for {
// 		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
// 		if certDERBlock == nil {
// 			break
// 		}
// 		if certDERBlock.Type == "CERTIFICATE" {
// 			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
// 		}
// 	}
// 	return cert
// }
