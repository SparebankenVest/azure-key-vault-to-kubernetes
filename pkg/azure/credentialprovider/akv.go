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
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/go-autorest/autorest"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
	"k8s.io/klog/v2"
)

const (
	vmTypeVMSS = "vmss"
)

// AzureKeyVaultCredentials has credentials needed to authenticate with azure key vault.
// These credentials will never expire
type AzureKeyVaultCredentials interface {
	Authorizer() (autorest.Authorizer, error)
	Endpoint(keyVaultName string) string
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c UserAssignedManagedIdentityProvider) GetAzureKeyVaultCredentials(azureIdentity string, hostname string) (azure.LegacyTokenCredential, error) {
	err := c.aadClient.Init()
	if err != nil {
		return nil, err
	}

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

	token, err := getServicePrincipalTokenFromMSI(c.environment.ActiveDirectoryEndpoint, azureIdentity, c.environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return azure.NewLegacyTokenCredentialAdal(token), nil
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c CloudConfigCredentialProvider) GetAzureKeyVaultCredentials() (azure.LegacyTokenCredential, error) {

	token, err := getServicePrincipalTokenFromCloudConfig(c.config, c.environment, c.environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return azure.NewLegacyTokenCredentialAdal(token), nil
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c EnvironmentCredentialProvider) GetAzureKeyVaultCredentials() (azure.LegacyTokenCredential, error) {
	azureToken, err := getCredentials(c.envSettings, c.envSettings.Environment.ResourceIdentifiers.KeyVault)
	if err != nil {
		return nil, err
	}

	return azure.NewLegacyTokenCredentialAdal(azureToken.token), nil

}

func getCredentialsNative() (azure.LegacyTokenCredential, error) {
	creds, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{})
	if err != nil {
		klog.ErrorS(err, "failed to create azure credentials provider, error: %+v", err)
		os.Exit(1)
	}
	return creds, nil
}

// GetAzureKeyVaultCredentials will get Azure credentials
func (c NativeCredentialProvider) GetAzureKeyVaultCredentials() (azure.LegacyTokenCredential, error) {
	return getCredentialsNative()
}
