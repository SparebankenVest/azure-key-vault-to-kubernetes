// Copyright © 2019 Sparebanken Vest
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Note: Code is based on azure_credentials.go in Kubernetes (https://github.com/kubernetes/kubernetes/blob/v1.17.9/pkg/credentialprovider/azure/azure_credentials.go)

package azure

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strings"

	"golang.org/x/crypto/pkcs12"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	docker "github.com/containers/image/v5/types"
	"github.com/spf13/pflag"

	azureAuth "github.com/Azure/go-autorest/autorest/azure/auth"
	log "github.com/sirupsen/logrus"
	"k8s.io/legacy-cloud-providers/azure/auth"
	"sigs.k8s.io/yaml"
)

var flagConfigFile = pflag.String("azure-container-registry-config", "",
	"Path to the file containing Azure container registry configuration information.")

const (
	maxReadLength = 10 * 1 << 20 // 10MB
)

var (
	containerRegistryUrls = []string{"*.azurecr.io", "*.azurecr.cn", "*.azurecr.de", "*.azurecr.us"}
	acrRE                 = regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)
)

// DockerConfig contains credentials used to access Docker regestries
type DockerConfig map[string]docker.DockerAuthConfig

// CloudConfigProvider provides credentials for Azure
type CloudConfigProvider struct {
	config                *auth.AzureAuthConfig
	environment           *azure.Environment
	servicePrincipalToken *adal.ServicePrincipalToken
}

// Credentials has credentials needed to authenticate with azure key vault.
// These credentials will never expire
type Credentials interface {
	Endpoint(name string) string
	Authorizer() (autorest.Authorizer, error)
}

type credentials struct {
	Token           *adal.ServicePrincipalToken
	EndpointPartial string
}

// OAuthCredentials has credentials need to authenticate with azure.
// These credentials expires when the oauth token expire (default one our in Azure). Use the
// Credentials interface if you want tokens to refresh.
type OAuthCredentials struct {
	OAuthToken      string `json:"oauth_token"`
	EndpointPartial string `json:"endpoint_partial"`
}

type crendentialsToken struct {
	token string
}

// NewFromCloudConfig parses the specified configFile and returns a DockerConfigProvider
func NewFromCloudConfig(configReader io.Reader) (*CloudConfigProvider, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	token, config, err := getServicePrincipalTokenFromCloudConfig(configReader, authSettings.Environment)

	if err != nil {
		return nil, err
	}

	return &CloudConfigProvider{
		config:                config,
		environment:           &authSettings.Environment,
		servicePrincipalToken: token,
	}, nil
}

// NewFromServicePrincipalToken gets a credentials object from a service principal token to use with Azure Key Vault
func NewFromServicePrincipalToken(token *adal.ServicePrincipalToken) (Credentials, error) {
	resourceSplit := strings.SplitAfterN(token.Token().Resource, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	return &credentials{
		Token:           token,
		EndpointPartial: endpoint,
	}, nil
}

// GetCredentials will get Azure credentials
func (c CloudConfigProvider) GetCredentials() (Credentials, error) {
	resourceSplit := strings.SplitAfterN(c.environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	return &credentials{
		Token:           c.servicePrincipalToken,
		EndpointPartial: endpoint,
	}, nil
}

// GetAcrCredentials will get Docker credentials for Azure Container Registry
func (c CloudConfigProvider) GetAcrCredentials(image string) (DockerConfig, error) {
	cfg := DockerConfig{}

	if c.config.UseManagedIdentityExtension {
		log.Debug("getting acr credentials using managed identity")
		if loginServer := parseACRLoginServerFromImage(image, c.environment); loginServer == "" {
			log.Infof("image(%s) is not from ACR, skip MSI authentication", image)
		} else {
			if cred, err := getACRDockerEntryFromARMToken(c.config, c.servicePrincipalToken, loginServer); err == nil {
				cfg[loginServer] = *cred
			}
		}
	} else {
		// Add our entry for each of the supported container registry URLs
		for _, url := range containerRegistryUrls {
			cred := &docker.DockerAuthConfig{
				Username: c.config.AADClientID,
				Password: c.config.AADClientSecret,
			}
			cfg[url] = *cred
		}

		// Handle the custom cloud case
		// In clouds where ACR is not yet deployed, the string will be empty
		if c.environment != nil && strings.Contains(c.environment.ContainerRegistryDNSSuffix, ".azurecr.") {
			customAcrSuffix := "*" + c.environment.ContainerRegistryDNSSuffix
			hasBeenAdded := false
			for _, url := range containerRegistryUrls {
				if strings.EqualFold(url, customAcrSuffix) {
					hasBeenAdded = true
					break
				}
			}

			if !hasBeenAdded {
				cred := &docker.DockerAuthConfig{
					Username: c.config.AADClientID,
					Password: c.config.AADClientSecret,
				}
				cfg[customAcrSuffix] = *cred
			}
		}
	}

	// add ACR anonymous repo support: use empty username and password for anonymous access
	cfg["*.azurecr.*"] = docker.DockerAuthConfig{
		Username: "",
		Password: "",
	}
	return cfg, nil
}

// NewFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewFromEnvironment() (Credentials, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	resourceSplit := strings.SplitAfterN(authSettings.Environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	akvCreds := &credentials{
		EndpointPartial: endpoint,
	}

	// ClientID / Secret
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

	// Certificate
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

	// Username / Password
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

	// User-Assigned Managed Identity
	if msi.ClientID != "" {
		token, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, authSettings.Environment.ResourceIdentifiers.KeyVault, msi.ClientID)
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	// System-Assigned Managed Identity
	token, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, authSettings.Environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}
	akvCreds.Token = token
	return akvCreds, nil
}

// Authorizer gets an Authorizer from credentials
func (c credentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromServicePrincipalToken(c.Token)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c credentials) Endpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c credentials) KeyVaultEndpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

func (t crendentialsToken) OAuthToken() string {
	return t.token
}

// MarshalJSON will get a fresh oauth token from the service principal token and serialize.
// This token will expire after the default oauth token lifetime for the service principal.
func (c credentials) MarshalJSON() ([]byte, error) {
	err := c.Token.Refresh()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token before marshalling, error: %+v", err)
	}

	return json.Marshal(&OAuthCredentials{
		OAuthToken:      c.Token.OAuthToken(),
		EndpointPartial: c.EndpointPartial,
	})
}

// Authorizer gets an Authorizer from credentials
func (c OAuthCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromOAuthToken(c.OAuthToken)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c OAuthCredentials) Endpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

func getServicePrincipalTokenFromCloudConfig(configReader io.Reader, env azure.Environment) (*adal.ServicePrincipalToken, *auth.AzureAuthConfig, error) {
	config, err := ParseConfig(configReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading cloud config, error: %+v", err)
	}

	if config.UseManagedIdentityExtension {
		log.Debug("azure: using managed identity extension to retrieve access token")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, nil, fmt.Errorf("failed getting the managed service identity endpoint: %+v", err)
		}

		if len(config.UserAssignedIdentityID) > 0 {
			log.Debug("azure: using User Assigned MSI ID to retrieve access token")
			token, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint,
				env.ResourceIdentifiers.KeyVault,
				config.UserAssignedIdentityID)

			return token, config, err
		}
		log.Debug("azure: using System Assigned MSI to retrieve access token")
		token, err := adal.NewServicePrincipalTokenFromMSI(
			msiEndpoint,
			env.ResourceIdentifiers.KeyVault)

		return token, config, err
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if len(config.AADClientSecret) > 0 {
		log.Debug("azure: using client_id+client_secret to retrieve access token")
		token, err := adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			env.ResourceIdentifiers.KeyVault)

		return token, config, err
	}

	if len(config.AADClientCertPath) > 0 && len(config.AADClientCertPassword) > 0 {
		log.Debug("azure: using jwt client_assertion (client_cert+client_private_key) to retrieve access token")
		certData, err := ioutil.ReadFile(config.AADClientCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the client certificate from file %s: %v", config.AADClientCertPath, err)
		}
		certificate, privateKey, err := decodePkcs12(certData, config.AADClientCertPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding the client certificate: %v", err)
		}
		token, err := adal.NewServicePrincipalTokenFromCertificate(
			*oauthConfig,
			config.AADClientID,
			certificate,
			privateKey,
			env.ResourceIdentifiers.KeyVault)
		return token, config, err
	}

	return nil, nil, fmt.Errorf("No credentials provided for AAD application %s", config.AADClientID)
}

func createAuthorizerFromServicePrincipalToken(token *adal.ServicePrincipalToken) (autorest.Authorizer, error) {
	err := token.Refresh()
	if err != nil {
		return nil, err
	}
	return createAuthorizerFromOAuthToken(token.OAuthToken())
}

func createAuthorizerFromOAuthToken(token string) (autorest.Authorizer, error) {
	tokenProvider := crendentialsToken{token: token}
	return autorest.NewBearerAuthorizer(tokenProvider), nil
}

// ParseConfig returns a parsed configuration for an Azure cloudprovider config file
func ParseConfig(configReader io.Reader) (*auth.AzureAuthConfig, error) {
	var config auth.AzureAuthConfig

	if configReader == nil {
		return &config, nil
	}

	limitedReader := &io.LimitedReader{R: configReader, N: maxReadLength}
	configContents, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if limitedReader.N <= 0 {
		return nil, errors.New("the read limit is reached")
	}
	err = yaml.Unmarshal(configContents, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func getACRDockerEntryFromARMToken(config *auth.AzureAuthConfig, token *adal.ServicePrincipalToken, loginServer string) (*docker.DockerAuthConfig, error) {
	// Run EnsureFresh to make sure the token is valid and does not expire
	if err := token.EnsureFresh(); err != nil {
		return nil, fmt.Errorf("Failed to ensure fresh service principal token: %v", err)
	}
	armAccessToken := token.OAuthToken()

	log.Debugf("discovering auth redirects for: %s", loginServer)
	directive, err := receiveChallengeFromLoginServer(loginServer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive challenge: %s", err)
	}

	log.Debug("exchanging an acr refresh_token")
	registryRefreshToken, err := performTokenExchange(loginServer, directive, config.TenantID, armAccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform token exchange: %s", err)
	}

	log.Debugf("adding ACR docker config entry for: %s", loginServer)
	return &docker.DockerAuthConfig{
		Username: dockerTokenLoginUsernameGUID,
		Password: registryRefreshToken,
	}, nil
}

// parseACRLoginServerFromImage takes image as parameter and returns login server of it.
// Parameter `image` is expected in following format: foo.azurecr.io/bar/imageName:version
// If the provided image is not an acr image, this function will return an empty string.
func parseACRLoginServerFromImage(image string, env *azure.Environment) string {
	match := acrRE.FindAllString(image, -1)
	if len(match) == 1 {
		return match[0]
	}

	// handle the custom cloud case
	if env != nil {
		cloudAcrSuffix := env.ContainerRegistryDNSSuffix
		cloudAcrSuffixLength := len(cloudAcrSuffix)
		if cloudAcrSuffixLength > 0 {
			customAcrSuffixIndex := strings.Index(image, cloudAcrSuffix)
			if customAcrSuffixIndex != -1 {
				endIndex := customAcrSuffixIndex + cloudAcrSuffixLength
				return image[0:endIndex]
			}
		}
	}

	return ""
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
