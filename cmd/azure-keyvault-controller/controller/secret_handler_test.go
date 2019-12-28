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

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	pemCert        = "-----BEGIN PRIVATE KEY-----\n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\nk125vXj8DvpA/GTS1kARDjKz8dET\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nMIIFUjCCAzqgAwIBAgIQFwNmpFLpQLWUtRrCdyrn0TANBgkqhkiG9w0BAQsFADAm\nMSQwIgYDVQQDExtjdW11bHVzLXRlc3QtY2VydC5zcHZlc3Qubm8wHhcNMTkwMjAx\nMTUzNjMxWhcNMTkwMzAxMTU0NjMxWjAmMSQwIgYDVQQDExtjdW11bHVzLXRlc3Qt\nY2VydC5zcHZlc3Qubm8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCv\nOy4KydxUOW6KmMhq01IAu5Rz47U1oE6ewq0Yi5ea9CrGN7eUWLOogapoKmFFhO2s\n5SDdPt9HOkDNvh75k4B7OFhM+GaOTRubXgPEg8PV7dFFS52+3C0xORdS+wvgI2i9\neIMqbr1Y8Znw5H3pLG8DsU6Q8FCo14mvW8/ou+xKbSOzWFFaP+dNHFBCARqI+DhQ\nYJFkeg4vPd+nFGxfPH/lbbR9WN0tChOTVUJlGkJlht9/0bsVmM8xAdUS/zQ6qK8n\nKWhLpCtWyo8zKDWg5gsdcMoWYgAIXpinc1NcOyGlMv263Zhw7gB+y7JEMK2Ro3e3\nSmhSpH48CkejpIsUOBNnvr514wkLNLet9sXGZvFXs7oiTkUzgu0MFsZPVAkiYhdH\ndYdg2I9e5t4yyxbu+DSr/OvRbUtC9PrO1ncJaO7p9QcXVuRNi2wxLDeaTZgd9S6M\n2fzR2xcwq3Fxk53gDlRTXgqIM/VCPA+3vp5di+MKGK7aLyNRPxeKcsDLEPHF7MeF\nZJw21xTupEMl8w5KaBd5NiKAwxbLyV8YCZFjJG3V2MOxVAA01BAm7w3lz1/iMbKi\nPGbDA0p3cxvaLYs0RdcNfZ6+4X7al7vBXj8+Hwf/tADY648eBEjTqctVDirElCmj\nN8A0ysqldwqCr+8F8k8PUfR3yb809m8QURE7mEAPVQIDAQABo3wwejAOBgNVHQ8B\nAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\nAwIwHwYDVR0jBBgwFoAUlJOHnXHhHeY+AjaPPmKFVRw3K1MwHQYDVR0OBBYEFJST\nh51x4R3mPgI2jz5ihVUcNytTMA0GCSqGSIb3DQEBCwUAA4ICAQAn/chFtfLEebP5\n5Tmb+H+eEzOXaHRonUsVriV/66htOeffkNX2b2DOIosvSwKukOkVggLFmyMKhxiq\neZkkAYyMMjjtWqbkCwoCyb8iDUQLaEovy4Pzwpm3YMVK9+o6cIf4zs3AgzaSSpbo\npq8HQbmFGrUGNEyGMclvf5VL1vCw+0jLpJ1+9b79DRY7puPG19zwWWcHk2hNV3aD\n6lWar7/pjqA9ESQhDTeUsXaFMGVm0Ez97IDI/ZVO+ia5+rIo5wAcUGKuYLIs57Wl\ndhlzMil3mz2g4STiWI+VhtPnqPot6MaWuKIN4R+kJocN365WJf2wozYgEjNFANK+\n3hO396cieWBTqyoYYZRxDxz7slD5NikixrJd50QshYCzqKiNopKsafqMHqc3JKZu\nz9tBZ25g43vdSuAwxjSab5DyYGF3Z447jdKOLUYReNnoB7nlTuW5LYfOX20F/XtC\n+4iL+IDjtAfwATruKzbLnKL9IoemLs7XMoW2qYBmCAcfHrI2F3alAar2XTA9lkDR\nMPpJf9q3VzxkPhjlvi8RPJfWLD1Kw4gMVfhao/NQv3SlhQ2rBpczP8XQOWdTNWp/\n043EPQis8+56AEHis/5+NKoNcQYZJwu2uwK0fdILcStJXR//EI04zBzWo/ULe5nc\nU0GaEMA+K/ZUHV2BxSMA3Br0IwdNvg==\n-----END CERTIFICATE-----\n"
	pemCertPubOnly = "-----BEGIN CERTIFICATE-----\nMIIFUjCCAzqgAwIBAgIQFwNmpFLpQLWUtRrCdyrn0TANBgkqhkiG9w0BAQsFADAm\nMSQwIgYDVQQDExtjdW11bHVzLXRlc3QtY2VydC5zcHZlc3Qubm8wHhcNMTkwMjAx\nMTUzNjMxWhcNMTkwMzAxMTU0NjMxWjAmMSQwIgYDVQQDExtjdW11bHVzLXRlc3Qt\nY2VydC5zcHZlc3Qubm8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCv\nOy4KydxUOW6KmMhq01IAu5Rz47U1oE6ewq0Yi5ea9CrGN7eUWLOogapoKmFFhO2s\n5SDdPt9HOkDNvh75k4B7OFhM+GaOTRubXgPEg8PV7dFFS52+3C0xORdS+wvgI2i9\neIMqbr1Y8Znw5H3pLG8DsU6Q8FCo14mvW8/ou+xKbSOzWFFaP+dNHFBCARqI+DhQ\nYJFkeg4vPd+nFGxfPH/lbbR9WN0tChOTVUJlGkJlht9/0bsVmM8xAdUS/zQ6qK8n\nKWhLpCtWyo8zKDWg5gsdcMoWYgAIXpinc1NcOyGlMv263Zhw7gB+y7JEMK2Ro3e3\nSmhSpH48CkejpIsUOBNnvr514wkLNLet9sXGZvFXs7oiTkUzgu0MFsZPVAkiYhdH\ndYdg2I9e5t4yyxbu+DSr/OvRbUtC9PrO1ncJaO7p9QcXVuRNi2wxLDeaTZgd9S6M\n2fzR2xcwq3Fxk53gDlRTXgqIM/VCPA+3vp5di+MKGK7aLyNRPxeKcsDLEPHF7MeF\nZJw21xTupEMl8w5KaBd5NiKAwxbLyV8YCZFjJG3V2MOxVAA01BAm7w3lz1/iMbKi\nPGbDA0p3cxvaLYs0RdcNfZ6+4X7al7vBXj8+Hwf/tADY648eBEjTqctVDirElCmj\nN8A0ysqldwqCr+8F8k8PUfR3yb809m8QURE7mEAPVQIDAQABo3wwejAOBgNVHQ8B\nAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\nAwIwHwYDVR0jBBgwFoAUlJOHnXHhHeY+AjaPPmKFVRw3K1MwHQYDVR0OBBYEFJST\nh51x4R3mPgI2jz5ihVUcNytTMA0GCSqGSIb3DQEBCwUAA4ICAQAn/chFtfLEebP5\n5Tmb+H+eEzOXaHRonUsVriV/66htOeffkNX2b2DOIosvSwKukOkVggLFmyMKhxiq\neZkkAYyMMjjtWqbkCwoCyb8iDUQLaEovy4Pzwpm3YMVK9+o6cIf4zs3AgzaSSpbo\npq8HQbmFGrUGNEyGMclvf5VL1vCw+0jLpJ1+9b79DRY7puPG19zwWWcHk2hNV3aD\n6lWar7/pjqA9ESQhDTeUsXaFMGVm0Ez97IDI/ZVO+ia5+rIo5wAcUGKuYLIs57Wl\ndhlzMil3mz2g4STiWI+VhtPnqPot6MaWuKIN4R+kJocN365WJf2wozYgEjNFANK+\n3hO396cieWBTqyoYYZRxDxz7slD5NikixrJd50QshYCzqKiNopKsafqMHqc3JKZu\nz9tBZ25g43vdSuAwxjSab5DyYGF3Z447jdKOLUYReNnoB7nlTuW5LYfOX20F/XtC\n+4iL+IDjtAfwATruKzbLnKL9IoemLs7XMoW2qYBmCAcfHrI2F3alAar2XTA9lkDR\nMPpJf9q3VzxkPhjlvi8RPJfWLD1Kw4gMVfhao/NQv3SlhQ2rBpczP8XQOWdTNWp/\n043EPQis8+56AEHis/5+NKoNcQYZJwu2uwK0fdILcStJXR//EI04zBzWo/ULe5nc\nU0GaEMA+K/ZUHV2BxSMA3Br0IwdNvg==\n-----END CERTIFICATE-----\n"
)

type fakeVaultService struct {
	fakeSecretValue string
	fakeCertValue   string
}

func (f *fakeVaultService) GetSecret(secret *akv.AzureKeyVault) (string, error) {
	if f.fakeSecretValue != "" {
		return f.fakeSecretValue, nil
	}
	return "", nil
}
func (f *fakeVaultService) GetKey(secret *akv.AzureKeyVault) (string, error) {
	return "", nil
}
func (f *fakeVaultService) GetCertificate(secret *akv.AzureKeyVault, exportPrivateKey bool) (*vault.Certificate, error) {
	if f.fakeCertValue != "" {
		return vault.NewCertificateFromPem(f.fakeCertValue)
	}
	return nil, nil
}

func secret() *akv.AzureKeyVaultSecret {
	return &akv.AzureKeyVaultSecret{
		TypeMeta: metav1.TypeMeta{APIVersion: akv.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-name",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: akv.AzureKeyVaultSecretSpec{
			Vault: akv.AzureKeyVault{
				Name: fmt.Sprintf("%s-vault-name", "test-name"),
				Object: akv.AzureKeyVaultObject{
					Name: "some-secret",
					Type: "secret",
				},
			},
		},
	}
}

func TestHandleMultiValueSecret(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: `firstValue: some first value data
secondValue: some second value data`,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "multi-value-secret"
	secret.Spec.Vault.Object.ContentType = "application/x-yaml"

	handler := NewAzureMultiKeySecretHandler(secret, fakeVault)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if len(values) != 2 {
		t.Errorf("number of values returned should be 2 but were %d", len(values))
	}
}

func TestHandleSecretWithNoDataKey(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: "Some very secret data",
	}

	secret := secret()
	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)
	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.Handle()
	if err == nil {
		t.Error("Should fail when no datakey is spesified")
	}
	if values != nil {
		t.Error("handler should not have returned values")
	}
}

func TestHandleCertificateWithTlsOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeCertValue: pemCert,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "certificate"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeTLS

	handler := NewAzureCertificateHandler(secret, fakeVault)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 2 {
		t.Error("handler should have returned 2 key/values")
	}
	if values[corev1.TLSCertKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.TLSCertKey)
	}
	if values[corev1.TLSPrivateKeyKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.TLSPrivateKeyKey)
	}
}

func TestHandlePubliKeyCertificateOnlyWithTlsOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeCertValue: pemCertPubOnly,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "certificate"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeTLS

	handler := NewAzureCertificateHandler(secret, fakeVault)
	_, err := handler.Handle()
	if err == nil {
		t.Error("Handler should fail because there are no private key in certificate")
	}
}

func TestHandlePubliKeyCertificateWithDataKey(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeCertValue: pemCertPubOnly,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "certificate"
	secret.Spec.Output.Secret.DataKey = "mykey"

	handler := NewAzureCertificateHandler(secret, fakeVault)
	values, err := handler.Handle()
	if err != nil {
		t.Error("Should have returned error because there is no private key")
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 1 {
		t.Error("handler should have returned 1 key/value")
	}
	if values[secret.Spec.Output.Secret.DataKey] == nil {
		t.Errorf("")
	}
}

func TestHandleCertificateFailureWithNoOutputDataKey(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeCertValue: pemCert,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "certificate"

	handler := NewAzureCertificateHandler(secret, fakeVault)
	values, err := handler.Handle()
	if err == nil {
		t.Error("Handler should fail because there are no dataKey defined")
	}
	if values != nil {
		t.Error("handler should not have returned values")
	}
}

func TestHandleCertificateWithOutputDataKey(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeCertValue: pemCert,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "certificate"
	secret.Spec.Output.Secret.DataKey = "my-key"

	handler := NewAzureCertificateHandler(secret, fakeVault)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 1 {
		t.Error("there should be only one value present")
	}
	if values[secret.Spec.Output.Secret.DataKey] == nil {
		t.Errorf("there should be a value stored for key %s", secret.Spec.Output.Secret.DataKey)
	}
}

func TestHandleCertificateWithRawOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeCertValue: pemCert,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "certificate"
	secret.Spec.Output.Secret.DataKey = "my-key"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeOpaque

	handler := NewAzureCertificateHandler(secret, fakeVault)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 1 {
		t.Error("there should be only one value present")
	}
	if values[secret.Spec.Output.Secret.DataKey] == nil {
		t.Errorf("there should be a value stored for key %s", secret.Spec.Output.Secret.DataKey)
	}
}

func TestHandleSecretWithBasicAuthOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: "myuser:mypassword",
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "secret"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeBasicAuth

	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)

	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 2 {
		t.Error("there should be two key/values present")
	}
	if values[corev1.BasicAuthUsernameKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.BasicAuthUsernameKey)
	}
	if values[corev1.BasicAuthPasswordKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.BasicAuthPasswordKey)
	}
}

func TestHandleSecretWithDockerConfigJsonAsOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: "lkajslfjalsdj",
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "secret"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeDockerConfigJson

	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)
	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 1 {
		t.Error("there should be only one key/value present")
	}
	if values[corev1.DockerConfigJsonKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.DockerConfigJsonKey)
	}
}

func TestHandleSecretWithDockerConfigAsOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: "lkajslfjalsdj",
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "secret"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeDockercfg

	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)
	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 1 {
		t.Error("there should be only one key/value present")
	}
	if values[corev1.DockerConfigKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.DockerConfigKey)
	}
}

func TestHandleSecretWithSSHAuthAsOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: "lkajslfjalsdj",
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "secret"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeSSHAuth

	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)
	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.Handle()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 1 {
		t.Error("there should be only one key/value present")
	}
	if values[corev1.SSHAuthPrivateKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.SSHAuthPrivateKey)
	}
}
