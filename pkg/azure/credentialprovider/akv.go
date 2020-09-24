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
	"fmt"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
)

// AzureKeyVaultCredentials has credentials needed to authenticate with azure key vault.
// These credentials will never expire
type AzureKeyVaultCredentials struct {
	Token           *adal.ServicePrincipalToken
	EndpointPartial string
}

// Authorizer gets an Authorizer from credentials
func (c AzureKeyVaultCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromServicePrincipalToken(c.Token)
}

// Endpoint takes the name of the keyvault and creates a correct andpoint url
func (c AzureKeyVaultCredentials) Endpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c CloudConfigCredentialProvider) GetAzureKeyVaultCredentials() (*AzureKeyVaultCredentials, error) {
	resourceSplit := strings.SplitAfterN(c.environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	token, err := getServicePrincipalTokenFromCloudConfig(c.config, c.environment, c.environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return &AzureKeyVaultCredentials{
		Token:           token,
		EndpointPartial: endpoint,
	}, nil
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c EnvironmentCredentialProvider) GetAzureKeyVaultCredentials() (*AzureKeyVaultCredentials, error) {
	resourceSplit := strings.SplitAfterN(c.envSettings.Environment.ResourceIdentifiers.KeyVault, "https://", 2)
	endpoint := resourceSplit[0] + "%s." + resourceSplit[1]

	akvCreds := &AzureKeyVaultCredentials{
		EndpointPartial: endpoint,
	}

	// ClientID / Secret
	if creds, err := c.envSettings.GetClientCredentials(); err == nil {
		creds.AADEndpoint = c.envSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = c.envSettings.Environment.ResourceIdentifiers.KeyVault

		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}

		akvCreds.Token = token
		return akvCreds, nil
	}

	// Certificate
	if creds, err := c.envSettings.GetClientCertificate(); err == nil {
		creds.AADEndpoint = c.envSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = c.envSettings.Environment.ResourceIdentifiers.KeyVault

		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	// Username / Password
	if creds, err := c.envSettings.GetUsernamePassword(); err == nil {
		creds.AADEndpoint = c.envSettings.Environment.ActiveDirectoryEndpoint
		creds.Resource = c.envSettings.Environment.ResourceIdentifiers.KeyVault

		token, err := creds.ServicePrincipalToken()
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	msi := c.envSettings.GetMSI()
	msiEndpoint, err := adal.GetMSIVMEndpoint()
	if err != nil {
		return nil, err
	}

	// User-Assigned Managed Identity
	if msi.ClientID != "" {
		token, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, c.envSettings.Environment.ResourceIdentifiers.KeyVault, msi.ClientID)
		if err != nil {
			return nil, err
		}
		akvCreds.Token = token
		return akvCreds, nil
	}

	// System-Assigned Managed Identity
	token, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, c.envSettings.Environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}
	akvCreds.Token = token
	return akvCreds, nil
}
