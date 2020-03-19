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
	getAuthorizer func() (autorest.Authorizer, error)
}

// AzureKeyVaultToken is a oauth token to use with Azure Key Vault
type AzureKeyVaultToken struct {
	token string
}

// OAuthToken gets the oauth token as string
func (t AzureKeyVaultToken) OAuthToken() string {
	return t.token
}

// NewAzureKeyVaultToken creates a new oauth token to use with Azure Key Vault
func NewAzureKeyVaultToken(token string) AzureKeyVaultToken {
	return AzureKeyVaultToken{
		token: token,
	}
}

// NewAzureKeyVaultCredentialsFromCloudConfig gets a credentials object from cloud config to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromCloudConfig(cloudConfigPath string) (*AzureKeyVaultCredentials, error) {
	config, err := readCloudConfig(cloudConfigPath)
	if err != nil {
		return nil, err
	}

	return NewAzureKeyVaultCredentialsFromClient(config.AADClientID, config.AADClientSecret, config.TenantID)
}

// NewAzureKeyVaultOauthTokenFromCloudConfig gets a oauth token from cloud config to use with Azure Key Vault
func NewAzureKeyVaultOauthTokenFromCloudConfig(cloudConfigPath string) (*AzureKeyVaultToken, error) {
	config, err := readCloudConfig(cloudConfigPath)
	if err != nil {
		return nil, err
	}

	return NewAzureKeyVaultOAuthTokenFromClient(config.AADClientID, config.AADClientSecret, config.TenantID)
}

// NewAzureKeyVaultOAuthTokenFromClient gets a oauth token from client credentials to use with Azure Key Vault
func NewAzureKeyVaultOAuthTokenFromClient(clientID, clientSecret, tenantID string) (*AzureKeyVaultToken, error) {
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

	conf, err := adal.NewOAuthConfig(cred.AADEndpoint, cred.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth config: %+v", err)
	}

	token, err := adal.NewServicePrincipalToken(*conf, cred.ClientID, cred.ClientSecret, azureEnvSettings.AzureKeyVaultURI)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %+v", err)
	}
	token.SetAutoRefresh(false)
	if err := token.Refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %+v", err)
	}

	return &AzureKeyVaultToken{
		token: token.OAuthToken(),
	}, nil
}

// NewAzureKeyVaultCredentialsFromOauthToken gets a credentials object from a oauth token to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromOauthToken(token string) (*AzureKeyVaultCredentials, error) {
	tokenProvider := AzureKeyVaultToken{token: token}
	authorizer := autorest.NewBearerAuthorizer(tokenProvider)

	return &AzureKeyVaultCredentials{
		getAuthorizer: func() (autorest.Authorizer, error) {
			return authorizer, nil
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
	}, nil
}

// NewAzureKeyVaultCredentialsFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromEnvironment() (*AzureKeyVaultCredentials, error) {
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
	}, nil
}

// Authorizer gets an Authorizer from credentials
func (c AzureKeyVaultCredentials) Authorizer() (autorest.Authorizer, error) {
	azureAuth.GetSettingsFromEnvironment()
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
