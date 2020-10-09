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
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
)

// AzureResourceManagerCredentials has credentials needed to authenticate with azure resource manager.
// These credentials will never expire
type AzureResourceManagerCredentials struct {
	SubscriptionID          string
	ResourceManagerEndpoint string
	Token                   *adal.ServicePrincipalToken
}

// Authorizer gets an Authorizer from credentials
func (c AzureResourceManagerCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromServicePrincipalToken(c.Token)
}

// GetAzureResourceManagerCredentials will get Azure credentials for Azure Resource Manager (ARM)
func (c CloudConfigCredentialProvider) GetAzureResourceManagerCredentials() (*AzureResourceManagerCredentials, error) {
	token, err := getServicePrincipalTokenFromCloudConfig(c.config, c.environment, c.environment.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	return &AzureResourceManagerCredentials{
		Token: token,
	}, nil
}
