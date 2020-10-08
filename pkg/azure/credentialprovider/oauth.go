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

	"github.com/Azure/go-autorest/autorest"
)

// OAuthCredentials has credentials need to authenticate with azure.
// These credentials expires when the oauth token expire (default one our in Azure). Use the
// Credentials interface if you want tokens to refresh.
type OAuthCredentials struct {
	OAuthToken      string `json:"oauth_token"`
	EndpointPartial string `json:"endpoint_partial"`
}

type crendentialsToken struct {
	token string
}

func (t crendentialsToken) OAuthToken() string {
	return t.token
}

// AzureKeyVaultEndpoint takes the name of the keyvault and creates a correct andpoint url
func (c OAuthCredentials) AzureKeyVaultEndpoint(keyVaultName string) string {
	return fmt.Sprintf(c.EndpointPartial, keyVaultName)
}

// Authorizer gets an Authorizer from credentials
func (c OAuthCredentials) Authorizer() (autorest.Authorizer, error) {
	return createAuthorizerFromOAuthToken(c.OAuthToken)
}
