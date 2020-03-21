package client

import (
	"fmt"
	"io/ioutil"

	"github.com/Azure/go-autorest/autorest"
	"gopkg.in/yaml.v2"

	"github.com/Azure/go-autorest/autorest/adal"
	azureAuth "github.com/Azure/go-autorest/autorest/azure/auth"
	cloudAuth "k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"
)

// AzureKeyVaultCredentials for service principal
type AzureKeyVaultCredentials struct {
	getAuthorizer      func() (autorest.Authorizer, error)
	getToken           func() (string, error)
	getCredentialsType func() (CredentialsType, error)

	envSettings azureAuth.EnvironmentSettings
}

// CredentialsType contains the credentials type for authentication
type CredentialsType string

const (
	// CredentialsTypeClusterCredentials represent Azure AKS cluster credentials
	CredentialsTypeClusterCredentials CredentialsType = "aksClusterCredentials"

	// CredentialsTypeClientCredentials represent Azure Client Credentials
	CredentialsTypeClientCredentials CredentialsType = "clientCredentials"

	// CredentialsTypeClientCertificate represent Azure Certificate Credentials
	CredentialsTypeClientCertificate CredentialsType = "clientCertficate"

	// CredentialsTypeClientUsernamePassword represent Azure Username Password Credentials
	CredentialsTypeClientUsernamePassword CredentialsType = "usernamePassword"

	// CredentialsTypeManagedIdentitiesForAzureResources represent Azure Managed Identities for Azure resources Credentials (formerly known as MSI)
	CredentialsTypeManagedIdentitiesForAzureResources CredentialsType = "managedIdentitiesForAzureResources"

	// CredentialsTypeToken represent an existing oauth token
	CredentialsTypeToken CredentialsType = "token"
)

// Authorizer gets an Authorizer from credentials
func (c AzureKeyVaultCredentials) Authorizer() (autorest.Authorizer, error) {
	azureAuth.GetSettingsFromEnvironment()
	return c.getAuthorizer()
}

// OAuthToken gets the oauth token as string
func (c AzureKeyVaultCredentials) OAuthToken() (string, error) {
	return c.getToken()
}

// CredentialsType gets the type of credentials used
func (c AzureKeyVaultCredentials) CredentialsType() (CredentialsType, error) {
	return c.getCredentialsType()
}

// EnvironmentSetting return the azure envionrment settings
func (c AzureKeyVaultCredentials) EnvironmentSettings() azureAuth.EnvironmentSettings {
	return c.envSettings
}

// NewAzureKeyVaultCredentialsFromCloudConfig gets a credentials object from cloud config to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromCloudConfig(cloudConfigPath string) (*AzureKeyVaultCredentials, error) {
	config, err := readCloudConfig(cloudConfigPath)
	if err != nil {
		return nil, err
	}

	creds, err := NewAzureKeyVaultCredentialsFromClient(config.AADClientID, config.AADClientSecret, config.TenantID)
	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			return creds.getAuthorizer()
		},
		getToken: func() (string, error) {
			return creds.getToken()
		},
		getCredentialsType: func() (CredentialsType, error) {
			return CredentialsTypeClusterCredentials, nil
		},
		envSettings: creds.envSettings,
	}, nil

}

type azureKeyVaultToken struct {
	token string
}

func (t azureKeyVaultToken) OAuthToken() string {
	return t.token
}

// NewAzureKeyVaultCredentialsFromOauthToken gets a credentials object from a oauth token to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromOauthToken(token string) (*AzureKeyVaultCredentials, error) {
	tokenProvider := azureKeyVaultToken{token: token}
	authorizer := autorest.NewBearerAuthorizer(tokenProvider)

	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			return authorizer, nil
		},
		getToken: func() (string, error) {
			return token, nil
		},
		getCredentialsType: func() (CredentialsType, error) {
			return CredentialsTypeToken, nil
		},
	}, nil
}

// NewAzureKeyVaultCredentialsFromClient creates a credentials object from a servbice principal to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromClient(clientID, clientSecret, tenantID string) (*AzureKeyVaultCredentials, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	azureEnvSettings, err := GetAzureEnvironmentSetting()
	if err != nil {
		return nil, fmt.Errorf("failed getting azure environment settings, err: %+v", err)
	}

	cred := azureAuth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
	cred.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
	cred.Resource = azureEnvSettings.AzureKeyVaultURI

	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			authorizer, err := cred.Authorizer()

			if err != nil {
				return nil, fmt.Errorf("failed to create authorizer based on service principal credentials, err: %+v", err)
			}
			return authorizer, nil
		},
		getToken: func() (string, error) {
			return getToken(cred)
		},
		getCredentialsType: func() (CredentialsType, error) {
			credType, _, err := getCredentialsType()
			return credType, err
		},
		envSettings: authSettings,
	}, nil
}

// NewAzureKeyVaultCredentialsFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromEnvironment() (*AzureKeyVaultCredentials, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			azureEnvSettings, err := GetAzureEnvironmentSetting()
			if err != nil {
				return nil, fmt.Errorf("failed getting azure environment settings, err: %+v", err)
			}

			authorizer, err := azureAuth.NewAuthorizerFromEnvironmentWithResource(azureEnvSettings.AzureKeyVaultURI)
			if err != nil {
				return nil, fmt.Errorf("failed to create authorizer from environment, err: %+v", err)
			}
			return authorizer, nil
		},
		getToken: func() (string, error) {
			return getTokenFromEnvironment()
		},
		getCredentialsType: func() (CredentialsType, error) {
			credType, _, err := getCredentialsType()
			return credType, err
		},
		envSettings: authSettings,
	}, nil
}

func getToken(creds azureAuth.ClientCredentialsConfig) (string, error) {
	token, err := creds.ServicePrincipalToken()
	if err != nil {
		return "", fmt.Errorf("failed to get service principal token: %+v", err)
	}

	token.SetAutoRefresh(false)
	if err := token.Refresh(); err != nil {
		return "", fmt.Errorf("failed to refresh token: %+v", err)
	}
	return token.OAuthToken(), nil
}

func getTokenFromEnvironment() (string, error) {
	credType, authSettings, err := getCredentialsType()
	if err != nil {
		return "", fmt.Errorf("failed to get credentials type: %+v", err)
	}

	azureEnvSettings, err := GetAzureEnvironmentSetting()
	if err != nil {
		return "", fmt.Errorf("failed getting azure environment settings, err: %+v", err)
	}

	var token *adal.ServicePrincipalToken

	switch credType {
	case CredentialsTypeClientCredentials:
		creds, err := authSettings.GetClientCredentials()
		if err != nil {
			return "", fmt.Errorf("failed to get client credentials: %+v", err)
		}
		creds.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = azureEnvSettings.AzureKeyVaultURI
		token, err = creds.ServicePrincipalToken()
		if err != nil {
			return "", fmt.Errorf("failed to get service principal token: %+v", err)
		}
	case CredentialsTypeClientCertificate:
		creds, err := authSettings.GetClientCertificate()
		if err != nil {
			return "", fmt.Errorf("failed to get client credentials: %+v", err)
		}
		creds.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = azureEnvSettings.AzureKeyVaultURI
		token, err = creds.ServicePrincipalToken()
		if err != nil {
			return "", fmt.Errorf("failed to get service principal token: %+v", err)
		}
	case CredentialsTypeClientUsernamePassword:
		creds, err := authSettings.GetUsernamePassword()
		if err != nil {
			return "", fmt.Errorf("failed to get client credentials: %+v", err)
		}
		creds.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = azureEnvSettings.AzureKeyVaultURI
		token, err = creds.ServicePrincipalToken()
		if err != nil {
			return "", fmt.Errorf("failed to get service principal token: %+v", err)
		}
	case CredentialsTypeManagedIdentitiesForAzureResources:
		msiEndpoint, err := adal.GetMSIEndpoint()
		if err != nil {
			return "", fmt.Errorf("failed to get MSI endpoint: %+v", err)
		}

		token, err = adal.NewServicePrincipalTokenFromMSI(msiEndpoint, azureEnvSettings.AzureKeyVaultURI)
		if err != nil {
			return "", fmt.Errorf("failed to get service principal token from managed identity: %+v", err)
		}
	}

	token.SetAutoRefresh(false)
	if err := token.Refresh(); err != nil {
		return "", fmt.Errorf("failed to refresh token: %+v", err)
	}
	return token.OAuthToken(), nil
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

func getCredentialsType() (CredentialsType, *azureAuth.EnvironmentSettings, error) {
	envSettings, err := azureAuth.GetSettingsFromEnvironment()
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
	if _, e := envSettings.GetMSI().Authorizer(); e == nil {
		return CredentialsTypeManagedIdentitiesForAzureResources, &envSettings, nil
	}

	return "", nil, fmt.Errorf("failed to automatically detect azure keyvault credentials")
}
