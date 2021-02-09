// Copyright © 2020 Sparebanken Vest
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

package credentialprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
)

const (
	vmTypeVMSS     = "vmss"
	vmTypeStandard = "standard"
)

type AzureKeyVaultCredentials interface {
	Authorizer() (autorest.Authorizer, error)
	Endpoint(keyVaultName string) string
}

// AzureKeyVaultCredentials has credentials needed to authenticate with azure key vault.
// These credentials will never expire
type keyVaultCredentials struct {
	ClientID        string
	Token           *adal.ServicePrincipalToken
	EndpointPartial string
}

// Authorizer gets an Authorizer from credentials
func (c *keyVaultCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromServicePrincipalToken(c.Token)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c *keyVaultCredentials) Endpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

// MarshalJSON will get a fresh oauth token from the service principal token and serialize.
// This token will expire after the default oauth token lifetime for the service principal.
func (c *keyVaultCredentials) MarshalJSON() ([]byte, error) {
	err := c.Token.Refresh()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token before marshalling, error: %+v", err)
	}

	return json.Marshal(&OAuthCredentials{
		OAuthToken:      c.Token.OAuthToken(),
		EndpointPartial: c.EndpointPartial,
	})
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c *UserAssignedManagedIdentityProvider) GetAzureKeyVaultCredentials(azureIdentity string, hostname string) (AzureKeyVaultCredentials, error) {
	err := c.aadClient.Init()
	if err != nil {
		return nil, err
	}

	resourceSplit := strings.SplitAfterN(c.environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]
	msiExists := false

	msis, err := c.aadClient.GetUserMSIs(hostname, c.config.VMType == vmTypeVMSS)
	if err != nil {
		return nil, err
	}

	for _, msi := range msis {
		if msi == azureIdentity {
			msiExists = true
			break
		}
	}

	if !msiExists {
		ids := []string{azureIdentity}
		err := c.aadClient.UpdateUserMSI(ids, []string{}, hostname, c.config.VMType == vmTypeVMSS)
		if err != nil {
			return nil, err
		}
	}

	token, err := getServicePrincipalTokenFromMSI(azureIdentity, c.environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return &keyVaultCredentials{
		Token:           token,
		EndpointPartial: endpoint,
	}, nil
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c CloudConfigCredentialProvider) GetAzureKeyVaultCredentials() (AzureKeyVaultCredentials, error) {
	resourceSplit := strings.SplitAfterN(c.environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	token, err := getServicePrincipalTokenFromCloudConfig(c.config, c.environment, c.environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return &keyVaultCredentials{
		Token:           token,
		EndpointPartial: endpoint,
	}, nil
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c EnvironmentCredentialProvider) GetAzureKeyVaultCredentials() (AzureKeyVaultCredentials, error) {
	resourceSplit := strings.SplitAfterN(c.envSettings.Environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	azureToken, err := getCredentials(c.envSettings, c.envSettings.Environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return &AzureKeyVaultCredentials{
		ClientID:        azureToken.clientID,
		Token:           azureToken.token,
		EndpointPartial: endpoint,
	}, nil

}
