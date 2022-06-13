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
	"testing"

	fakeVault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client/fake"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
	corev1 "k8s.io/api/core/v1"
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
	fakeJsonSecret = `{
		"someKey": "someValue",
		"someOtherKey": "someOtherValue"
	}`
	fakeYamlSecret = `
someKey: someValue
someOtherKey: someOtherValue`
)

func TestSyncAzureKeyVaultMultiKeyVauleJson(t *testing.T) {
	c := &Controller{
		vaultService: &fakeVault.AkvsService{
			FakeSecret: fakeJsonSecret,
		},
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
	if len(res) != 2 {
		t.Error("expected secret with two keys")
	}

	key, ok := res["someKey"]
	if !ok {
		t.Error("expected key 'someKey'")
	}

	if string(key) != "someValue" {
		t.Error("expected value of key 'someKey' to be 'someValue'")
	}

	key, ok = res["someOtherKey"]
	if !ok {
		t.Error("expected key 'someOtherKey'")
	}

	if string(key) != "someOtherValue" {
		t.Error("expected value of key 'someOtherKey' to be 'someOtherValue'")
	}
}

func TestSyncAzureKeyVaultMultiKeyVauleYaml(t *testing.T) {
	c := &Controller{
		vaultService: &fakeVault.AkvsService{
			FakeSecret: fakeYamlSecret,
		},
	}

	akvs := &akv.AzureKeyVaultSecret{
		Spec: akv.AzureKeyVaultSecretSpec{
			Vault: akv.AzureKeyVault{
				Object: akv.AzureKeyVaultObject{
					Type:        akv.AzureKeyVaultObjectTypeMultiKeyValueSecret,
					ContentType: akv.AzureKeyVaultObjectContentTypeYaml,
				},
			},
		},
	}

	res, err := c.getSecretFromKeyVault(akvs)
	if err != nil {
		t.Error(err)
	}
	if len(res) != 2 {
		t.Error("expected secret with two keys")
	}

	key, ok := res["someKey"]
	if !ok {
		t.Error("expected key 'someKey'")
	}

	if string(key) != "someValue" {
		t.Error("expected value of key 'someKey' to be 'someValue'")
	}

	key, ok = res["someOtherKey"]
	if !ok {
		t.Error("expected key 'someOtherKey'")
	}

	if string(key) != "someOtherValue" {
		t.Error("expected value of key 'someOtherKey' to be 'someOtherValue'")
	}
}

func TestSyncAzureKeyVaultMultiKeyVauleDoesNotAllowOutputSecretType(t *testing.T) {
	c := &Controller{
		vaultService: &fakeVault.AkvsService{
			FakeSecret: fakeYamlSecret,
		},
	}

	akvs := &akv.AzureKeyVaultSecret{
		Spec: akv.AzureKeyVaultSecretSpec{
			Vault: akv.AzureKeyVault{
				Object: akv.AzureKeyVaultObject{
					Type:        akv.AzureKeyVaultObjectTypeMultiKeyValueSecret,
					ContentType: akv.AzureKeyVaultObjectContentTypeYaml,
				},
			},
			Output: akv.AzureKeyVaultOutput{
				Secret: akv.AzureKeyVaultOutputSecret{
					Type: corev1.SecretTypeDockercfg,
				},
			},
		},
	}

	res, err := c.getSecretFromKeyVault(akvs)
	if err != nil {
		t.Error(err)
	}
	if len(res) != 2 {
		t.Error("expected secret with two keys")
	}

	key, ok := res["someKey"]
	if !ok {
		t.Error("expected key 'someKey'")
	}

	if string(key) != "someValue" {
		t.Error("expected value of key 'someKey' to be 'someValue'")
	}

	key, ok = res["someOtherKey"]
	if !ok {
		t.Error("expected key 'someOtherKey'")
	}

	if string(key) != "someOtherValue" {
		t.Error("expected value of key 'someOtherKey' to be 'someOtherValue'")
	}
}
