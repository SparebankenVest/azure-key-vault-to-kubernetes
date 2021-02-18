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

package fake

import (
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
)

// AkvsService is a fake service used for testing
type AkvsService struct {
	FakeSecret string
	FakeKey    string
	FakeCert   *vault.Certificate
}

func (s *AkvsService) GetSecret(secret *akv.AzureKeyVault) (string, error) {
	return s.FakeSecret, nil
}

func (s *AkvsService) GetKey(secret *akv.AzureKeyVault) (string, error) {
	return s.FakeKey, nil
}

func (s *AkvsService) GetCertificate(secret *akv.AzureKeyVault, options *vault.CertificateOptions) (*vault.Certificate, error) {
	return s.FakeCert, nil
}
