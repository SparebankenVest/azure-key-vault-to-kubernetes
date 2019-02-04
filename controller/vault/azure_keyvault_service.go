package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/pkcs12"
	corev1 "k8s.io/api/core/v1"

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

const (
	AzureKeyVaultCertificateTypePem string = "application/x-pem-file"
	AzureKeyVaultCertificateTypePfx        = "application/x-pkcs12"
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
	switch secret.Spec.Vault.Object.Type {
	case AzureKeyVaultObjectTypeCertificate:
		return getCertificate(secret)
	default:
		return getSecret(secret)
	}
}

func getSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (map[string][]byte, error) {
	if secret.Spec.Vault.Object.Name == "" {
		return nil, fmt.Errorf("azurekeyvaultsecret.spec.vault.object.name not set")
	}

	secretValue := make(map[string][]byte, 1)

	//Get secret value from Azure Key Vault
	vaultClient, err := getClient("https://vault.azure.net")
	if err != nil {
		return secretValue, err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
	secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.Object.Name, secret.Spec.Vault.Object.Version)

	if err != nil {
		return secretValue, err
	}

	secretValue[secret.Spec.Output.Secret.DataKey] = []byte(*secretBundle.Value)

	// TODO: Add support for using Keys

	// if secret.Spec.OutputSecret.Key != "" {
	// } else {
	// 	for _, key := range secret.Spec.OutputSecret.Keys {
	// 		secretValue[key.DstName] = []byte(*secretBundle.Value)
	// 	}
	// }

	return secretValue, nil
}

// getCertificate return public/private certificate pems
func getCertificate(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (map[string][]byte, error) {
	secretValue := make(map[string][]byte, 2)

	//Get secret value from Azure Key Vault
	vaultClient, err := getClient("https://vault.azure.net")
	if err != nil {
		return secretValue, err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)

	certBundle, err := vaultClient.GetCertificate(context.Background(), baseURL, secret.Spec.Vault.Object.Name, secret.Spec.Vault.Object.Version)
	if err != nil {
		return secretValue, fmt.Errorf("failed to get certificate from azure key vault, error: %+v", err)
	}

	if !*certBundle.Policy.KeyProperties.Exportable {
		return nil, fmt.Errorf("unable to get certificate since it's not exportable")
	}

	secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.Object.Name, secret.Spec.Vault.Object.Version)
	if err != nil {
		return secretValue, fmt.Errorf("failed to get secret from azure key vault, error: %+v", err)
	}

	switch *secretBundle.ContentType {
	case AzureKeyVaultCertificateTypePem:
		return extractPemCertificate(*secretBundle.Value), nil
	case AzureKeyVaultCertificateTypePfx:
		return extractPfxCertificate(*secretBundle.Value)
	default:
		return secretValue, fmt.Errorf("azure key vault secret with content-type '%s' not supported", *secretBundle.ContentType)
	}
}

func extractPemCertificate(pemCert string) map[string][]byte {
	// TODO: Support cert chains
	secretValue := make(map[string][]byte, 2)
	privateDer, rest := pem.Decode([]byte(pemCert))
	publicDer, _ := pem.Decode(rest)

	secretValue[corev1.TLSCertKey] = pem.EncodeToMemory(publicDer)
	secretValue[corev1.TLSPrivateKeyKey] = pem.EncodeToMemory(privateDer)
	return secretValue
}

func extractPfxCertificate(pfx string) (map[string][]byte, error) {
	secretValue := make(map[string][]byte, 2)

	// log.Infof("Trying to decode base64 string: %s", pfx)
	//
	pfxRaw, err := base64.StdEncoding.DecodeString(pfx)
	if err != nil {
		return secretValue, fmt.Errorf("failed to decode base64 encoded pfx certificate, error: %+v", err)
	}

	pemList, err := pkcs12.ToPEM([]byte(pfxRaw), "")
	if err != nil {
		return secretValue, fmt.Errorf("failed to convert pfx certificate to pem, error: %+v", err)
	}

	var mergedPems bytes.Buffer
	for _, pemCert := range pemList {
		mergedPems.WriteString(string(pem.EncodeToMemory(pemCert)))
	}

	return extractPemCertificate(mergedPems.String()), nil
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
