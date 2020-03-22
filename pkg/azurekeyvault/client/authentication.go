package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"gopkg.in/yaml.v2"

	"github.com/Azure/go-autorest/autorest/adal"
	azureAuth "github.com/Azure/go-autorest/autorest/azure/auth"
	cloudAuth "k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"
)

// AzureKeyVaultCredentials has credentials needed to authenticate with azure key vault.
// These credentials will never expire
type AzureKeyVaultCredentials interface {
	Endpoint(keyVaultName string) string
	Authorizer() (autorest.Authorizer, error)
}

type azureKeyVaultCredentials struct {
	Token           *adal.ServicePrincipalToken
	EndpointPartial string
}

type azureKeyVaultToken struct {
	token string
}

// AzureKeyVaultOAuthCredentials has credentials need to authenticate with azure key vault.
// These credentials expires when the oauth token expire (default one our in Azure). Use the
// AzureKeyVaultCredentials interface if you want tokens to refresh.
type AzureKeyVaultOAuthCredentials struct {
	OAuthToken      string `json:"oauth_token"`
	EndpointPartial string `json:"endpoint_partial"`
}

// Authorizer gets an Authorizer from credentials
func (c azureKeyVaultCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromServicePrincipalToken(c.Token)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c azureKeyVaultCredentials) Endpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

// MarshalJSON will get a fresh oauth token from the service principal token and serialize.
// This token will expire after the default oauth token lifetime for the service principal.
func (c azureKeyVaultCredentials) MarshalJSON() ([]byte, error) {
	err := c.Token.Refresh()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token before marshalling, error: %+v", err)
	}

	return json.Marshal(&AzureKeyVaultOAuthCredentials{
		OAuthToken:      c.Token.OAuthToken(),
		EndpointPartial: c.EndpointPartial,
	})
}

func createAuthorizerFromServicePrincipalToken(token *adal.ServicePrincipalToken) (autorest.Authorizer, error) {
	err := token.Refresh()
	if err != nil {
		return nil, err
	}
	return createAuthorizerFromOAuthToken(token.OAuthToken())
}

func (t azureKeyVaultToken) OAuthToken() string {
	return t.token
}

func createAuthorizerFromOAuthToken(token string) (autorest.Authorizer, error) {
	tokenProvider := azureKeyVaultToken{token: token}
	return autorest.NewBearerAuthorizer(tokenProvider), nil
}

// NewAzureKeyVaultCredentialsFromCloudConfig gets a credentials object from cloud config to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromCloudConfig(cloudConfigPath string) (AzureKeyVaultCredentials, error) {
	config, err := readCloudConfig(cloudConfigPath)
	if err != nil {
		return nil, err
	}

	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	token, err := cloudAuth.GetServicePrincipalToken(config, &authSettings.Environment)
	resourceSplit := strings.SplitAfterN(authSettings.Environment.KeyVaultEndpoint, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	return &azureKeyVaultCredentials{
		Token:           token,
		EndpointPartial: endpoint,
	}, nil
}

// NewAzureKeyVaultCredentialsFromServicePrincipalToken gets a credentials object from a service principal token to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromServicePrincipalToken(token *adal.ServicePrincipalToken) (AzureKeyVaultCredentials, error) {
	resourceSplit := strings.SplitAfterN(token.Token().Resource, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	return &azureKeyVaultCredentials{
		Token:           token,
		EndpointPartial: endpoint,
	}, nil
}

// Authorizer gets an Authorizer from credentials
func (c AzureKeyVaultOAuthCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromOAuthToken(c.OAuthToken)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c AzureKeyVaultOAuthCredentials) Endpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

// // NewAzureKeyVaultCredentialsFromOauthToken gets a credentials object from a oauth token to use with Azure Key Vault
// func NewAzureKeyVaultCredentialsFromOauthToken(data []byte) (AzureKeyVaultCredentials, error) {
// 	var creds AzureKeyVaultOAuthCredentials
// 	json.Unmarshal(data, &creds)

// 	return creds, nil
// }

// NewAzureKeyVaultCredentialsFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromEnvironment() (AzureKeyVaultCredentials, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	resourceSplit := strings.SplitAfterN(authSettings.Environment.KeyVaultEndpoint, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	akvCreds := &azureKeyVaultCredentials{
		EndpointPartial: endpoint,
	}

	if creds, err := authSettings.GetClientCredentials(); err == nil {
		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	if creds, err := authSettings.GetClientCertificate(); err == nil {
		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	if creds, err := authSettings.GetUsernamePassword(); err == nil {
		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	msi := authSettings.GetMSI()
	msiEndpoint, err := adal.GetMSIVMEndpoint()
	if err != nil {
		return nil, err
	}

	if msi.ClientID != "" {
		token, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, msi.Resource, msi.ClientID)
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	} else {
		token, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, msi.Resource)
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}
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
