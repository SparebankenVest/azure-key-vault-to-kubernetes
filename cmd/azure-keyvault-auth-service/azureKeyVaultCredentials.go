package main

import (
	"fmt"

	"github.com/Azure/go-autorest/autorest/azure/auth"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
)

// CredentialsType contains the credentials type for authentication
type CredentialsType string

const (
	// CredentialsTypeClusterCredentials represent Azure AKS cluster credentials
	CredentialsTypeClusterCredentials CredentialsType = "clusterCredentials"

	// CredentialsTypeClientCredentials represent Azure Client Credentials
	CredentialsTypeClientCredentials CredentialsType = "clientCredentials"

	// CredentialsTypeClientCertificate represent Azure Certificate Credentials
	CredentialsTypeClientCertificate CredentialsType = "clientCertficate"

	// CredentialsTypeClientUsernamePassword represent Azure Username Password Credentials
	CredentialsTypeClientUsernamePassword CredentialsType = "usernamePassword"

	// CredentialsTypeManagedIdentitiesForAzureResources represent Azure Managed Identities for Azure resources Credentials (formerly known as MSI)
	CredentialsTypeManagedIdentitiesForAzureResources CredentialsType = "managedIdentitiesForAzureResources"
)

// AzureKeyVaultCredentials convert Azure Key Vault credentials to Kubernetes Secret
type AzureKeyVaultCredentials struct {
	CredentialsType CredentialsType
	envSettings     *auth.EnvironmentSettings
}

// NewCredentials represents a set of Azure credentials
func NewCredentials() (*AzureKeyVaultCredentials, error) {
	credType, envSettings, err := getCredentialsType()
	if err != nil {
		return nil, err
	}

	return &AzureKeyVaultCredentials{
		CredentialsType: credType,
		envSettings:     envSettings,
	}, nil
}

// GetAzureToken uses current credentials to get a oauth token from Azure
func (c *AzureKeyVaultCredentials) GetAzureToken() (string, error) {
	switch c.CredentialsType {
	case CredentialsTypeClusterCredentials:
		token, err := vault.NewAzureKeyVaultOauthTokenFromCloudConfig(config.cloudConfigHostPath)
		if err != nil {
			return "", fmt.Errorf("failed to get oauth token: %+v", err)
		}
		return token.OAuthToken(), nil

	case CredentialsTypeClientCredentials:
		creds, err := c.envSettings.GetClientCredentials()
		if err != nil {
			return "", fmt.Errorf("failed to get client credentials: %+v", err)
		}

		token, err := vault.NewAzureKeyVaultOAuthTokenFromClient(creds.ClientID, creds.ClientSecret, creds.TenantID)

		return token.OAuthToken(), nil
	default:
		return "", fmt.Errorf("credential type %s not currently supported for token", c.CredentialsType)
	}
}

func getCredentialsType() (CredentialsType, *auth.EnvironmentSettings, error) {
	envSettings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return "", nil, fmt.Errorf("failed to automatically detect azure keyvault credentials, error: %+v", err)
	}

	//1.Client Credentials
	if _, e := envSettings.GetClientCredentials(); e == nil {
		return CredentialsTypeClientCredentials, &envSettings, nil
	}

	//2. Client Certificate
	if _, e := envSettings.GetClientCertificate(); e == nil {
		return CredentialsTypeClientCertificate, &envSettings, nil
	}

	//3. Username Password
	if _, e := envSettings.GetUsernamePassword(); e == nil {
		return CredentialsTypeClientUsernamePassword, &envSettings, nil
	}

	// 4. MSI
	if envSettings.GetMSI().ClientID != "" {
		return CredentialsTypeManagedIdentitiesForAzureResources, &envSettings, nil
	}

	return "", nil, fmt.Errorf("failed to automatically detect azure keyvault credentials")
}
