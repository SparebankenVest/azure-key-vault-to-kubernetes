package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
)

// GetSecret returns a secret from Azure Key Vault
func GetSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
	//Get secret value from Azure Key Vault
	vaultClient := getKeysClient("https://vault.azure.net")
	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
	secretPack, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")
	if err != nil {
		log.Printf("failed to get Key Vault Secret, Error: %+v", err)
		return "", err
	}
	return *secretPack.Value, nil
}

func getKeysClient(resource string) keyvault.BaseClient {
	log.Printf("Getting keys from Azure Key Vault...")

	keyClient := keyvault.New()

	msiEndpoint, err := adal.GetMSIVMEndpoint()
	if err != nil {
		log.Printf("failed to get msiendpoint, %+v", err)
		return keyClient
	}

	spt, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, resource)
	if err != nil {
		log.Printf("failed to acquire a token using the MSI VM extension, Error: %+v", err)
		return keyClient
	}

	keyClient.Authorizer = autorest.NewBearerAuthorizer(spt)

	return keyClient
}
