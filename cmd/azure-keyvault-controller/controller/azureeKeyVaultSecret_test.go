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

	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azure/keyvault/v2alpha1"
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
