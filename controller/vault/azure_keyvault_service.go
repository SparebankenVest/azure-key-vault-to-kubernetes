package vault

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	log "github.com/sirupsen/logrus"
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
	vaultClient, err := a.getKeysClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
	secretPack, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

	if err != nil {
		return "", err
	}
	return *secretPack.Value, nil
}

func (a *AzureKeyVaultService) getKeysClient(resource string) (*keyvault.BaseClient, error) {
	keyClient := keyvault.New()

	var authorizer autorest.Authorizer

	var err error
	if authorizer, err = auth.NewAuthorizerFromEnvironment(); err != nil {
		if err != nil {
			log.Warning("azure: failed to get authorizer from environment, will try MSI directly")

			msiEndpoint, err := adal.GetMSIVMEndpoint()
			if err != nil {
				return nil, fmt.Errorf("azure: failed to get msiendpoint, %+v", err)
			}

			spt, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, resource)
			if err != nil {
				return nil, fmt.Errorf("failed to acquire a token using the MSI VM extension, Error: %+v", err)
			}
			authorizer = autorest.NewBearerAuthorizer(spt)
		}
	}

	keyClient.Authorizer = authorizer

	return &keyClient, nil
}
