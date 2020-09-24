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

// Todo: Needs refactoring

package credentialprovider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/pkcs12"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
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

// CloudConfigCredentialProvider provides credentials for Azure using the cloud config file
type CloudConfigCredentialProvider struct {
	config      *auth.AzureAuthConfig
	environment *azure.Environment
}

// EnvironmentCredentialProvider provides credentials for Azure using environment vars
type EnvironmentCredentialProvider struct {
	envSettings *azureAuth.EnvironmentSettings
}

// Credentials has credentials needed to authenticate with azure key vault.
// These credentials will never expire
type Credentials interface {
	Authorizer() (autorest.Authorizer, error)
}

type credentials struct {
	Token           *adal.ServicePrincipalToken
	EndpointPartial string
}

// NewFromCloudConfig parses the specified configFile and returns a DockerConfigProvider
func NewFromCloudConfig(configReader io.Reader) (*CloudConfigCredentialProvider, error) {
	config, err := ParseConfig(configReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading cloud config, error: %+v", err)
	}

	env, err := auth.ParseAzureEnvironment(config.Cloud)
	if err != nil {
		return nil, fmt.Errorf("failed to parse environment from cloud config, error: %+v", err)
	}

	return &CloudConfigCredentialProvider{
		config:      config,
		environment: env,
	}, nil
}

// NewFromEnvironment creates a credentials object based on available environment settings to use with Azure Key Vault
func NewFromEnvironment() (*EnvironmentCredentialProvider, error) {
	envSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	return &EnvironmentCredentialProvider{
		envSettings: &envSettings,
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

// Authorizer gets an Authorizer from credentials
func (c credentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromServicePrincipalToken(c.Token)
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

func getServicePrincipalTokenFromCloudConfig(config *auth.AzureAuthConfig, env *azure.Environment, resource string) (*adal.ServicePrincipalToken, error) {
	if config.UseManagedIdentityExtension {
		log.Debug("azure: using managed identity extension to retrieve access token")
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, fmt.Errorf("failed getting the managed service identity endpoint: %+v", err)
		}

		if len(config.UserAssignedIdentityID) > 0 {
			log.Debug("azure: using User Assigned MSI ID to retrieve access token")
			token, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint,
				resource,
				config.UserAssignedIdentityID)

			return token, err
		}
		log.Debug("azure: using System Assigned MSI to retrieve access token")
		token, err := adal.NewServicePrincipalTokenFromMSI(
			msiEndpoint,
			resource)

		return token, err
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if len(config.AADClientSecret) > 0 {
		log.Debug("azure: using client_id+client_secret to retrieve access token")
		token, err := adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			resource)

		return token, err
	}

	if len(config.AADClientCertPath) > 0 && len(config.AADClientCertPassword) > 0 {
		log.Debug("azure: using jwt client_assertion (client_cert+client_private_key) to retrieve access token")
		certData, err := ioutil.ReadFile(config.AADClientCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading the client certificate from file %s: %v", config.AADClientCertPath, err)
		}
		certificate, privateKey, err := decodePkcs12(certData, config.AADClientCertPassword)
		if err != nil {
			return nil, fmt.Errorf("decoding the client certificate: %v", err)
		}
		token, err := adal.NewServicePrincipalTokenFromCertificate(
			*oauthConfig,
			config.AADClientID,
			certificate,
			privateKey,
			resource)
		return token, err
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", config.AADClientID)
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
