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

package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
)

type AzureKeyVaultToken struct {
	token string
}

func (t AzureKeyVaultToken) OAuthToken() string {
	return t.token
}

func NewAzureKeyVaultToken(token string) AzureKeyVaultToken {
	return AzureKeyVaultToken{
		token: token,
	}
}

func TestGetAzureToken(t *testing.T) {
	os.Setenv("AZURE_CLIENT_ID", "435e6a5e-e28f-455e-83ef-71a106fd4c32")
	os.Setenv("AZURE_CLIENT_SECRET", "ViFaAo-w4tiI48X]6J]SVUQ=V5BZM[lY")
	os.Setenv("AZURE_TENANT_ID", "417918a5-f594-44e0-ba27-23112940bde5")

	azureCreds, err := NewCredentials()
	if err != nil {
		t.Error(err)
	}

	token, err := azureCreds.GetAzureToken()
	if err != nil {
		t.Error(err)
	}
	newToken := NewAzureKeyVaultToken(token)

	authorizer := autorest.NewBearerAuthorizer(newToken)

	client := keyvault.New()
	client.Authorizer = authorizer

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", "akv2k8s-test")
	secretBundle, err := client.GetSecret(context.Background(), baseURL, "my-secret", "")
	if err != nil {
		t.Error(err)
	}
	if secretBundle.Value == nil {
		t.Error(fmt.Errorf("Failed"))
	}
}
