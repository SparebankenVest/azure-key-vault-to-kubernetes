package main

import (
	"log"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
)

// var (
// 	retryWaitTime  = pflag.Int("retry-wait-time", 20, "retry wait time in seconds")
// 	resource       = pflag.String("aad-resourcename", "https://management.azure.com/", "name of resource to grant token")
// 	subscriptionID = pflag.String("subscriptionid", "", "subscription id for test")
// 	clientID       = pflag.String("clientid", "", "client id for the msi id")
// 	resourceGroup  = pflag.String("resourcegroup", "", "any resource group name with reader permission to the aad object")
// )

// GetKeysClient returns a client to inteact with Azure Key Vault
func GetKeysClient(resource string) keyvault.BaseClient {
	log.Printf("Getting keys from Azure Key Vault...")

	keyClient := keyvault.New()

	// msiEndpoint, err := adal.GetMSIVMEndpoint()
	// if err != nil {
	// 	log.Printf("failed to get msiendpoint, %+v", err)
	// 	return keyClient
	// }
	//
	// servicePrincipal, err := adal.NewServicePrincipalTokenFromMSI(msiEndpoint, resource)
	// if err != nil {
	// 	log.Printf("failed to acquire a token using the MSI VM extension, Error: %+v", err)
	// 	return keyClient
	// }
	//
	// log.Printf("Service Principal created from MSI")
	//
	// if err := servicePrincipal.Refresh(); err != nil {
	// 	log.Printf("failed to refresh ServicePrincipalTokenFromMSI using the MSI VM extension, msiEndpoint(%s)", msiEndpoint)
	// 	return keyClient
	// }
	//
	// token := servicePrincipal.Token()
	// if token.IsZero() {
	// 	log.Printf("zero token found, MSI VM extension, msiEndpoint(%s)", msiEndpoint)
	// 	return keyClient
	// }
	//

	// authorizer, err := auth.NewAuthorizerFromEnvironment()

	// if err != nil {
	// 	log.Printf("failed NewAuthorizerFromEnvironment  %+v", authorizer)
	// 	return keyClient
	// }

	// token, err := GetKeyvaultToken(AuthGrantType(), "", tenantID, true, "", clientID, podName, podNamespace)

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

	if err := spt.Refresh(); err != nil {
		log.Printf("failed to refresh ServicePrincipalTokenFromMSI using the MSI VM extension, msiEndpoint(%s)", msiEndpoint)
		return keyClient
	}

	token := spt.Token()
	if token.IsZero() {
		log.Printf("zero token found, MSI VM extension, msiEndpoint(%s)", msiEndpoint)
		return keyClient
	}

	if err != nil {
		log.Printf("failed to get key vault token %+v", err)
		return keyClient
	}

	keyClient.Authorizer = autorest.NewBearerAuthorizer(spt)

	return keyClient
}
