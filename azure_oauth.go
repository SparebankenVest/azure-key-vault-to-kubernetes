// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

const (
	nmiendpoint   = "http://localhost:2579/host/token/"
	podnameheader = "podname"
	podnsheader   = "podns"
)

var (
	oauthConfig *adal.OAuthConfig
)

// OAuthGrantType specifies which grant type to use.
type OAuthGrantType int

const (
	// OAuthGrantTypeServicePrincipal for client credentials flow
	OAuthGrantTypeServicePrincipal OAuthGrantType = iota
	// OAuthGrantTypeDeviceFlow for device-auth flow
	OAuthGrantTypeDeviceFlow
)

// AzureAuthConfig holds auth related part of cloud config
type AzureAuthConfig struct {
	// The cloud environment identifier. Takes values from https://github.com/Azure/go-autorest/blob/ec5f4903f77ed9927ac95b19ab8e44ada64c1356/autorest/azure/environments.go#L13
	Cloud string `json:"cloud"`
	// The AAD Tenant ID for the Subscription that the cluster is deployed in
	TenantID string `json:"tenantId"`
	// The ClientID for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientID string `json:"aadClientId"`
	// The ClientSecret for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientSecret string `json:"aadClientSecret"`
	// The path of a client certificate for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientCertPath string `json:"aadClientCertPath"`
	// The password of the client certificate for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientCertPassword string `json:"aadClientCertPassword"`
	// Use managed service identity integrated with pod identity to get access to Azure ARM resources
	UsePodIdentity bool `json:"usePodIdentity"`
	// The ID of the Azure Subscription that the cluster is deployed in
	SubscriptionID string `json:"subscriptionId"`
}

// Config holds the configuration parsed from the --cloud-config flag
// All fields are required unless otherwise specified
type Config struct {
	AzureAuthConfig
	// Resource Group for cluster
	ResourceGroup string `json:"resourceGroup"`
	// The kms provider vault name
	ProviderVaultName string `json:"providerVaultName"`
	// The kms provider key name
	ProviderKeyName string `json:"providerKeyName"`
	// The kms provider key version
	ProviderKeyVersion string `json:"providerKeyVersion"`
}

func AuthGrantType() OAuthGrantType {
	return OAuthGrantTypeServicePrincipal
}

type NMIResponse struct {
	Token    adal.Token `json:"token"`
	ClientID string     `json:"clientid"`
}

func GetManagementToken(grantType OAuthGrantType, cloudName string, tenantId string, usePodIdentity bool, aADClientSecret string, aADClientID string, podname string, podns string) (authorizer autorest.Authorizer, err error) {

	env, err := ParseAzureEnvironment(cloudName)
	if err != nil {
		return nil, err
	}

	rmEndPoint := env.ResourceManagerEndpoint
	servicePrincipalToken, err := GetServicePrincipalToken(tenantId, env, rmEndPoint, usePodIdentity, aADClientSecret, aADClientID, podname, podns)
	if err != nil {
		return nil, err
	}
	authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	return authorizer, nil

}

func GetKeyvaultToken(grantType OAuthGrantType, cloudName string, tenantId string, usePodIdentity bool, aADClientSecret string, aADClientID string, podname string, podns string) (authorizer autorest.Authorizer, err error) {

	env, err := ParseAzureEnvironment(cloudName)
	if err != nil {
		return nil, err
	}

	kvEndPoint := env.KeyVaultEndpoint
	if '/' == kvEndPoint[len(kvEndPoint)-1] {
		kvEndPoint = kvEndPoint[:len(kvEndPoint)-1]
	}

	log.Printf("tenantId: %s", tenantId)
	log.Printf("kvEndPoint: %s", kvEndPoint)
	log.Printf("usePodIdentity: %t", usePodIdentity)
	log.Printf("podname: %s", podname)
	log.Printf("podns: %s", podns)

	servicePrincipalToken, err := GetServicePrincipalToken(tenantId, env, kvEndPoint, usePodIdentity, aADClientSecret, aADClientID, podname, podns)
	if err != nil {
		return nil, err
	}
	authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	return authorizer, nil

}

// GetServicePrincipalToken creates a new service principal token based on the configuration
func GetServicePrincipalToken(tenantId string, env *azure.Environment, resource string, usePodIdentity bool, aADClientSecret string, aADClientID string, podname string, podns string) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, tenantId)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	// For usepodidentity mode, the flexvolume driver makes an authorization request to fetch token for a resource from the NMI host endpoint (http://127.0.0.1:2579/host/token/).
	// The request includes the pod namespace `podns` and the pod name `podname` in the request header and the resource endpoint of the resource requesting the token.
	// The NMI server identifies the pod based on the `podns` and `podname` in the request header and then queries k8s (through MIC) for a matching azure identity.
	// Then nmi makes an adal request to get a token for the resource in the request, returns the `token` and the `clientid` as a reponse to the flexvolume request.

	if usePodIdentity {
		log.Printf("azure: using pod identity to retrieve token")

		endpoint := fmt.Sprintf("%s?resource=%s", nmiendpoint, resource)
		client := &http.Client{}
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add(podnsheader, podns)
		req.Header.Add(podnameheader, podname)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			var nmiResp = new(NMIResponse)
			err = json.Unmarshal(bodyBytes, &nmiResp)
			if err != nil {
				return nil, err
			}

			r, _ := regexp.Compile("^(\\S{4})(\\S|\\s)*(\\S{4})$")
			fmt.Printf("\n accesstoken: %s\n", r.ReplaceAllString(nmiResp.Token.AccessToken, "$1##### REDACTED #####$3"))
			fmt.Printf("\n clientid: %s\n", r.ReplaceAllString(nmiResp.ClientID, "$1##### REDACTED #####$3"))

			token := nmiResp.Token
			clientID := nmiResp.ClientID

			if &token == nil || clientID == "" {
				return nil, fmt.Errorf("nmi did not return expected values in response: token and clientid")
			}

			spt, err := adal.NewServicePrincipalTokenFromManualToken(*oauthConfig, clientID, resource, token, nil)
			if err != nil {
				return nil, err
			}
			return spt, nil
		}

		err = fmt.Errorf("nmi response failed with status code: %d", resp.StatusCode)
		return nil, err
	}
	// When flexvolume driver is using a Service Principal clientid + client secret to retrieve token for resource
	if len(aADClientSecret) > 0 {
		log.Printf("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			aADClientID,
			aADClientSecret,
			resource)
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", aADClientID)
}

// ParseAzureEnvironment returns azure environment by name
func ParseAzureEnvironment(cloudName string) (*azure.Environment, error) {
	var env azure.Environment
	var err error
	if cloudName == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(cloudName)
	}
	return &env, err
}
