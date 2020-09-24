package client

import (
	"fmt"
	"os"
	"strings"
	"testing"

	akv2k8sTesting "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/testing"
	auth "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	akvs "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func secret(name string, keyVaultName string, secretName string) *akvs.AzureKeyVaultSecret {
	return &akvs.AzureKeyVaultSecret{
		TypeMeta: metav1.TypeMeta{APIVersion: akvs.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: akvs.AzureKeyVaultSecretSpec{
			Vault: akvs.AzureKeyVault{
				Name: keyVaultName,
				Object: akvs.AzureKeyVaultObject{
					Name: secretName,
					Type: "secret",
				},
			},
		},
	}
}

func TestIntegrationGetSecret(t *testing.T) {
	akv2k8sTesting.EnsureIntegrationEnvironment(t)

	tenantId := os.Getenv("AZURE_TENANT_ID")
	subscriptionId := os.Getenv("AZURE_SUBSCRIPTION_ID")
	clientId := os.Getenv("AZURE_CLIENT_ID")
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
}`, tenantId, subscriptionId, clientId, clientSecret)

	r := strings.NewReader(config)

	provider, err := auth.NewFromCloudConfig(r)
	if err != nil {
		t.Error(err)
	}

	creds, err := provider.GetAzureKeyVaultCredentials()
	if err != nil {
		t.Error(err)
	}

	srvc := NewService(creds)
	akvSecret := secret("mySecret", "akv2k8s-test", "my-secret")

	secret, err := srvc.GetSecret(&akvSecret.Spec.Vault)
	if err != nil {
		t.Error(err)
	}

	if secret == "" {
		t.Fail()
	}

}

func TestIntegrationEnvironmentGetSecret(t *testing.T) {
	akv2k8sTesting.EnsureIntegrationEnvironment(t)

	provider, err := auth.NewFromEnvironment()
	if err != nil {
		t.Error(err)
	}

	creds, err := provider.GetAzureKeyVaultCredentials()
	if err != nil {
		t.Error(err)
	}

	srvc := NewService(creds)
	akvSecret := secret("mySecret", "akv2k8s-test", "my-secret")

	secret, err := srvc.GetSecret(&akvSecret.Spec.Vault)
	if err != nil {
		t.Error(err)
	}

	if secret == "" {
		t.Fail()
	}

}
