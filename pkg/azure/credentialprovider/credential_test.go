/*
Copyright Sparebanken Vest

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package credentialprovider

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Azure/go-autorest/autorest/azure"
	akv2k8sTesting "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/testing"
)

// func TestAuthDefault(t *testing.T) {
// 	creds, err := NewAzureKeyVaultCredentialsFromEnvironment()
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	_, err = creds.
// 	if err == nil {
// 		t.Fail()
// 	}
// }

// func TestChinaCloud(t *testing.T) {
// 	ensureIntegrationEnvironment(t)

// 	os.Setenv("AZURE_ENVIRONMENT", "AzureChinaCloud")

// 	creds, err := NewFromEnvironment()
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	token := creds.(*credentials).Token
// 	err = token.Refresh()
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	if token.Token().Resource != azure.ChinaCloud.ResourceIdentifiers.KeyVault {
// 		t.Errorf("Endpoint incorrect. Expected '%s', but got '%s'", azure.ChinaCloud.ResourceIdentifiers.KeyVault, token.Token().Resource)
// 	}
// }

func TestIntegrationACRTokenAuth(t *testing.T) {
	akv2k8sTesting.EnsureIntegrationEnvironment(t)

}

func TestIntegrationAuthFromUserAssignedManagedIdentity(t *testing.T) {
	akv2k8sTesting.EnsureIntegrationEnvironment(t)

	// provider, err := NewUserAssignedManagedIdentityProvider()
}

func TestIntegrationAuthFromEnvironmentAudience(t *testing.T) {
	akv2k8sTesting.EnsureIntegrationEnvironment(t)

	provider, err := NewFromEnvironment()
	if err != nil {
		t.Error(err)
	}

	creds, err := provider.GetAzureKeyVaultCredentials()
	if err != nil {
		t.Error(err)
	}

	token := creds.(azureKeyVaultCredentials).Token
	err = token.Refresh()
	if err != nil {
		t.Error(err)
	}

	if token.Token().Resource != azure.PublicCloud.ResourceIdentifiers.KeyVault {
		t.Errorf("expected resource uri '%s', got '%s'", azure.PublicCloud.ResourceIdentifiers.KeyVault, token.Token().Resource)
	}
}

func TestIntegrationAuthFromConfigAudience(t *testing.T) {
	akv2k8sTesting.EnsureIntegrationEnvironment(t)

	tenantID := os.Getenv("AZURE_TENANT_ID")
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

	config := fmt.Sprintf(`{
    "cloud":"AzurePublicCloud",
    "tenantId": "%s",
    "subscriptionId": "%s",
    "aadClientId": "%s",
    "aadClientSecret": "%s",
		"resourceGroup": "",
    "location": "westeurope",
    "vmType": "vmss",
    "subnetName": "",
    "securityGroupName": "",
    "vnetName": "",
    "vnetResourceGroup": "",
    "routeTableName": "",
    "primaryAvailabilitySetName": "",
    "primaryScaleSetName": "",
    "cloudProviderBackoffMode": "v2",
    "cloudProviderBackoff": true,
    "cloudProviderBackoffRetries": 6,
    "cloudProviderBackoffDuration": 5,
    "cloudProviderRatelimit": true,
    "cloudProviderRateLimitQPS": 10,
    "cloudProviderRateLimitBucket": 100,
    "cloudProviderRatelimitQPSWrite": 10,
    "cloudProviderRatelimitBucketWrite": 100,
    "useManagedIdentityExtension": false,
    "userAssignedIdentityID": "",
    "useInstanceMetadata": true,
    "loadBalancerSku": "Standard",
    "disableOutboundSNAT": false,
    "excludeMasterFromStandardLB": true,
    "providerVaultName": "",
    "maximumLoadBalancerRuleCount": 250,
    "providerKeyName": "k8s",
    "providerKeyVersion": ""
}`, tenantID, subscriptionID, clientID, clientSecret)

	r := strings.NewReader(config)

	conf, err := NewFromCloudConfig(r)
	if err != nil {
		t.Error(err)
	}

	creds, err := conf.GetAzureKeyVaultCredentials()
	if err != nil {
		t.Error(err)
	}

	token := creds.(azureKeyVaultCredentials).Token
	err = token.Refresh()
	if err != nil {
		t.Error(err)
	}

	if token.Token().Resource != azure.PublicCloud.ResourceIdentifiers.KeyVault {
		t.Errorf("expected resource uri '%s', got '%s'", azure.PublicCloud.ResourceIdentifiers.KeyVault, token.Token().Resource)
	}
}
