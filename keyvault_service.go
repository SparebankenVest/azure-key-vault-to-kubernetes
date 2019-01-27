package main

import (
	"github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2018-02-14/keyvault"
)

// GetSecret returns a secret from Azure Key Vault
func GetSecret(name String) {
	client := getKeysClient()

}

func getKeysClient() keyvault.BaseClient {
	keyClient := keyvault.New()
	a, _ := iam.GetKeyvaultAuthorizer()
	keyClient.Authorizer = a
	keyClient.AddToUserAgent(config.UserAgent())
	return keyClient
}
