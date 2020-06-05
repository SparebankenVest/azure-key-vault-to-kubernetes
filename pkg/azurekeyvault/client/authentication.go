package client

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"
	"gopkg.in/yaml.v2"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
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
		return nil, fmt.Errorf("failed reading cloud config, error: %+v", err)
	}

	var envName string
	if v := os.Getenv(azureAuth.EnvironmentName); v != "" {
		envName = v
	} else {
		envName = config.Cloud
	}

	environment, err := azure.EnvironmentFromName(envName)
	if err != nil {
		return nil, fmt.Errorf("invalid env name %s, error: %+v", envName, err)
	}

	token, err := getServicePrincipalTokenFromCloudConfig(config, environment)
	if err != nil {
		return nil, fmt.Errorf("failed getting service principal token, err: %+v", err)
	}

	resourceSplit := strings.SplitAfterN(environment.ResourceIdentifiers.KeyVault, "https://", 2)
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

// NewAzureKeyVaultCredentialsFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewAzureKeyVaultCredentialsFromEnvironment() (AzureKeyVaultCredentials, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	resourceSplit := strings.SplitAfterN(authSettings.Environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	akvCreds := &azureKeyVaultCredentials{
		EndpointPartial: endpoint,
	}

	if creds, err := authSettings.GetClientCredentials(); err == nil {
		creds.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = authSettings.Environment.ResourceIdentifiers.KeyVault

		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}

		akvCreds.Token = token
		return akvCreds, nil
	}

	if creds, err := authSettings.GetClientCertificate(); err == nil {
		creds.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = authSettings.Environment.ResourceIdentifiers.KeyVault

		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	if creds, err := authSettings.GetUsernamePassword(); err == nil {
		creds.AADEndpoint = authSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = authSettings.Environment.ResourceIdentifiers.KeyVault

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
	}

	token, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, msi.Resource)
	if err != nil {
		return nil, err
	}
	akvCreds.Token = token
	return akvCreds, nil
}

func getServicePrincipalTokenFromCloudConfig(config *cloudAuth.AzureAuthConfig, env azure.Environment) (*adal.ServicePrincipalToken, error) {
	if config.UseManagedIdentityExtension {
		// klog.V(2).Infoln("azure: using managed identity extension to retrieve access token")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("failed getting the managed service identity endpoint: %+v", err)
		}

		if len(config.UserAssignedIdentityID) > 0 {
			// klog.V(4).Info("azure: using User Assigned MSI ID to retrieve access token")
			return adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint,
				env.ResourceIdentifiers.KeyVault,
				config.UserAssignedIdentityID)
		}
		// klog.V(4).Info("azure: using System Assigned MSI to retrieve access token")
		return adal.NewServicePrincipalTokenFromMSI(
			msiEndpoint,
			env.ResourceIdentifiers.KeyVault)
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if len(config.AADClientSecret) > 0 {
		// klog.V(2).Infoln("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			env.ResourceIdentifiers.KeyVault)
	}

	if len(config.AADClientCertPath) > 0 && len(config.AADClientCertPassword) > 0 {
		// klog.V(2).Infoln("azure: using jwt client_assertion (client_cert+client_private_key) to retrieve access token")
		certData, err := ioutil.ReadFile(config.AADClientCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading the client certificate from file %s: %v", config.AADClientCertPath, err)
		}
		certificate, privateKey, err := decodePkcs12(certData, config.AADClientCertPassword)
		if err != nil {
			return nil, fmt.Errorf("decoding the client certificate: %v", err)
		}
		return adal.NewServicePrincipalTokenFromCertificate(
			*oauthConfig,
			config.AADClientID,
			certificate,
			privateKey,
			env.ResourceIdentifiers.KeyVault)
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", config.AADClientID)
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

func decodePkcs12(pkcs []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, certificate, err := pkcs12.Decode(pkcs, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding the PKCS#12 client certificate: %v", err)
	}
	rsaPrivateKey, isRsaKey := privateKey.(*rsa.PrivateKey)
	if !isRsaKey {
		return nil, nil, fmt.Errorf("PKCS#12 certificate must contain a RSA private key")
	}

	return certificate, rsaPrivateKey, nil
}
