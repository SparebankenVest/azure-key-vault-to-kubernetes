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

package controller

import (
	"fmt"
	"testing"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
)

func TestNullLookup(t *testing.T) {
	secret := akv.AzureKeyVaultSecret{
		Spec: akv.AzureKeyVaultSecretSpec{
			Output: akv.AzureKeyVaultOutput{
				Secret: akv.AzureKeyVaultOutputSecret{
					// Name: "laskjdflj",
				},
			},
		},
	}
	if secret.Spec.Output.Secret.Name != "" {
		t.Fail()
	}
}

const (
	fakeSecret     = "some secret"
	fakeJsonSecret = `{
		"someKey": "someValue",
		"someOtherKey": "someOtherValue"
	}`
	fakeYamlSecret = `
someKey: someValue
someOtherKey: someOtherValue`
)

type fakeAkvsService struct {
}

func (s *fakeAkvsService) GetSecret(secret *akv.AzureKeyVault) (string, error) {
	switch secret.Object.Type {
	case akv.AzureKeyVaultObjectTypeSecret:
		return fakeSecret, nil
	case akv.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		return fakeJsonSecret, nil
	default:
		return nil, fmt.Errorf("secret type not supported")
	}
}

func (s *fakeAkvsService) GetKey(secret *akv.AzureKeyVault) (string, error) {
	return "some key", nil
}

func (s *fakeAkvsService) GetCertificate(secret *akv.AzureKeyVault, options *client.CertificateOptions) (*client.Certificate, error) {
	return nil, nil
}

func TestGetAkvs(t *testing.T) {
	c := &Controller{
		vaultService: &fakeAkvsService{},
	}

	akvs := &akv.AzureKeyVaultSecret{
		Spec: akv.AzureKeyVaultSecretSpec{
			Vault: akv.AzureKeyVault{
				Object: akv.AzureKeyVaultObject{
					Type:        akv.AzureKeyVaultObjectTypeMultiKeyValueSecret,
					ContentType: akv.AzureKeyVaultObjectContentTypeJSON,
				},
			},
		},
	}

	res, err := c.getSecretFromKeyVault(akvs)
	if err != nil {
		t.Error(err)
	}
	if len(res) > 0 {

	}
}
