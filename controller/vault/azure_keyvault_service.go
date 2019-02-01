package vault

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
)

// AzureKeyVaultService provide interaction with Azure Key Vault
type AzureKeyVaultService struct {
	servicePrincipal *AzureServicePrincipal
}

// AzureServicePrincipal contains Azure Service Principal credentials
type AzureServicePrincipal struct {
	ServicePrincipalID     string
	ServicePrincipalSecret string
}

// NewAzureKeyVaultService creates a new AzureKeyVaultService using built in Managed Service Identity for authentication
func NewAzureKeyVaultService() *AzureKeyVaultService {
	return &AzureKeyVaultService{}
}

// NewAzureKeyVaultServiceWithServicePrincipal creates a new AzureKeyVaultService using Service Principal for authentication
func NewAzureKeyVaultServiceWithServicePrincipal(sp *AzureServicePrincipal) *AzureKeyVaultService {
	return &AzureKeyVaultService{
		servicePrincipal: sp,
	}
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

	if a.servicePrincipal != nil {
		var err error
		if authorizer, err = auth.NewAuthorizerFromEnvironment(); err != nil {
			return nil, fmt.Errorf("azure: failed to get authorizer from environment, %+v", err)
		}
	} else {
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

	keyClient.Authorizer = authorizer

	return &keyClient, nil
}
