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
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"

	aadProvider "github.com/Azure/aad-pod-identity/pkg/cloudprovider"
	azureAuth "github.com/Azure/go-autorest/autorest/azure/auth"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

const (
	maxReadLength = 10 * 1 << 20 // 10MB
)

// CloudConfigCredentialProvider provides credentials for Azure using the cloud config file
type UserAssignedManagedIdentityProvider struct {
	config      *AzureCloudConfig
	environment *azure.Environment
	aadClient   *aadProvider.Client
}

// CloudConfigCredentialProvider provides credentials for Azure using the cloud config file
type CloudConfigCredentialProvider struct {
	config      *AzureCloudConfig
	environment *azure.Environment
	aadClient   *aadProvider.Client
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

func NewUserAssignedManagedIdentityProvider(azureConfigFile string) (*UserAssignedManagedIdentityProvider, error) {
	aadClient, err := aadProvider.NewCloudProvider(azureConfigFile, 2, time.Second*30)
	if err != nil {
		return nil, fmt.Errorf("failed creating aad cloud provider, error: %+v", err)
	}

	return &UserAssignedManagedIdentityProvider{
		aadClient: aadClient,
	}, nil
}

// NewFromCloudConfig parses the specified configFile and returns a CloudConfigCredentialProvider
func NewFromCloudConfig(configReader io.Reader) (*CloudConfigCredentialProvider, error) {
	config, err := ParseConfig(configReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading cloud config, error: %+v", err)
	}

	env, err := parseAzureEnvironment(config.Cloud)
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

func getServicePrincipalTokenFromMSI(userAssignedIdentityID string, resource string) (*adal.ServicePrincipalToken, error) {
	// err := adal.AddToUserAgent(akv2k8s.)
	// if err != nil {
	// 	return fmt.Errorf("failed to add MIC to user agent, error: %+v", err)
	// }

	klog.V(4).InfoS("azure: using managed identity extension to retrieve access token", "id", userAssignedIdentityID)
	msiEndpoint, err := adal.GetMSIVMEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed getting the managed service identity endpoint: %+v", err)
	}

	if len(userAssignedIdentityID) > 0 {
		klog.V(4).InfoS("azure: using User Assigned MSI ID to retrieve access token", "id", userAssignedIdentityID, "url", msiEndpoint)
		token, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, resource, userAssignedIdentityID)
		if err != nil {
			return nil, fmt.Errorf("failed getting user assigned msi token from endpoint '%s': %+v", msiEndpoint, err)
		}
		return token, err
	}

	klog.V(4).InfoS("azure: using System Assigned MSI to retrieve access token", "url", msiEndpoint)
	token, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, resource)
	if err != nil {
		return nil, fmt.Errorf("failed getting system assigned msi token from endpoint '%s': %+v", msiEndpoint, err)
	}

	return token, err

}
func getServicePrincipalTokenFromCloudConfig(config *AzureCloudConfig, env *azure.Environment, resource string) (*adal.ServicePrincipalToken, error) {
	if config.UseManagedIdentityExtension {
		return getServicePrincipalTokenFromMSI(config.UserAssignedIdentityID, resource)
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if len(config.AADClientSecret) > 0 {
		klog.V(4).InfoS("azure: using client_id+client_secret to retrieve access token", "id", config.AADClientID)
		token, err := adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			resource)

		return token, err
	}

	if len(config.AADClientCertPath) > 0 && len(config.AADClientCertPassword) > 0 {
		klog.V(4).InfoS("azure: using jwt client_assertion (client_cert+client_private_key) to retrieve access token", "path", config.AADClientCertPath)
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

// AzureCloudConfig holds azure configuration
type AzureCloudConfig struct {
	// The cloud environment identifier. Takes values from https://github.com/Azure/go-autorest/blob/ec5f4903f77ed9927ac95b19ab8e44ada64c1356/autorest/azure/environments.go#L13
	Cloud string `json:"cloud,omitempty" yaml:"cloud,omitempty"`
	// The AAD Tenant ID for the Subscription that the cluster is deployed in
	TenantID string `json:"tenantId,omitempty" yaml:"tenantId,omitempty"`
	// The ClientID for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientID string `json:"aadClientId,omitempty" yaml:"aadClientId,omitempty"`
	// The ClientSecret for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientSecret string `json:"aadClientSecret,omitempty" yaml:"aadClientSecret,omitempty"`
	// The path of a client certificate for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientCertPath string `json:"aadClientCertPath,omitempty" yaml:"aadClientCertPath,omitempty"`
	// The password of the client certificate for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientCertPassword string `json:"aadClientCertPassword,omitempty" yaml:"aadClientCertPassword,omitempty"`
	// Use managed service identity for the virtual machine to access Azure ARM APIs
	UseManagedIdentityExtension bool `json:"useManagedIdentityExtension,omitempty" yaml:"useManagedIdentityExtension,omitempty"`
	// UserAssignedIdentityID contains the Client ID of the user assigned MSI which is assigned to the underlying VMs. If empty the user assigned identity is not used.
	// More details of the user assigned identity can be found at: https://docs.microsoft.com/en-us/azure/active-directory/managed-service-identity/overview
	// For the user assigned identity specified here to be used, the UseManagedIdentityExtension has to be set to true.
	UserAssignedIdentityID string `json:"userAssignedIdentityID,omitempty" yaml:"userAssignedIdentityID,omitempty"`
	// The location of the resource group that the cluster is deployed in
	Location string `json:"location,omitempty" yaml:"location,omitempty"`
	VMType   string `json:"vmType,omitempty" yaml:"vmType,omitempty"`
}

// ParseConfig returns a parsed configuration for an Azure cloudprovider config file
func ParseConfig(configReader io.Reader) (*AzureCloudConfig, error) {
	var config AzureCloudConfig

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

func parseAzureEnvironment(cloudName string) (*azure.Environment, error) {
	var env azure.Environment
	var err error
	if cloudName == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(cloudName)
	}
	return &env, err
}
