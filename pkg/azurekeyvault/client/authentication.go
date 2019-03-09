package client

import (
	"fmt"
	"io/ioutil"

	"github.com/Azure/go-autorest/autorest"
	"gopkg.in/yaml.v2"

	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureAuth "github.com/Azure/go-autorest/autorest/azure/auth"
	cloudAuth "k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"
)

const azureKeyVaultResourceURI = "https://vault.azure.net"

// AzureKeyVaultCredentials for service principal
type AzureKeyVaultCredentials struct {
	getAuthorizer func() (autorest.Authorizer, error)
}

// NewAzureKeyVaultCredentialsFromCloudConfig gets a credentials object from cloud config to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromCloudConfig(cloudConfigPath string) (*AzureKeyVaultCredentials, error) {
	config, err := readCloudConfig(cloudConfigPath)
	if err != nil {
		return nil, err
	}

	return NewAzureKeyVaultCredentialsFromClient(config.AADClientID, config.AADClientSecret, config.TenantID)
}

// NewAzureKeyVaultCredentialsFromClient creates a credentials object from a servbice principal to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromClient(clientID, clientSecret, tenantID string) (*AzureKeyVaultCredentials, error) {
	cred := azureAuth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
	cred.Resource = azureKeyVaultResourceURI

	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			authorizer, err := cred.Authorizer()
			if err != nil {
				return nil, fmt.Errorf("failed to create authorizer based on service principal credentials, err: %+v", err)
			}
			return authorizer, nil
		},
	}, nil
}

// NewAzureKeyVaultCredentialsFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromEnvironment() (*AzureKeyVaultCredentials, error) {
	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(azureKeyVaultResourceURI)
			if err != nil {
				return nil, fmt.Errorf("failed to create authorizer from environment, err: %+v", err)
			}
			return authorizer, nil
		},
	}, nil
}

// Authorizer gets an Authorizer from credentials
func (c AzureKeyVaultCredentials) Authorizer() (autorest.Authorizer, error) {
	return c.getAuthorizer()
}

func readCloudConfig(path string) (*cloudAuth.AzureAuthConfig, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cloud config file in an effort to get credentials for azure key vault, error: %+v", err)
	}

	azureConfig := cloudAuth.AzureAuthConfig{}
	if err = yaml.Unmarshal(bytes, &azureConfig); err != nil {
		return nil, fmt.Errorf("Unmarshall error: %v", err)
	}
	return &azureConfig, nil
}
