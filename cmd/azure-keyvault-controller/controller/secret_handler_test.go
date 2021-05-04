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
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	pemCert        = "-----BEGIN PRIVATE KEY-----\n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\nk125vXj8DvpA/GTS1kARDjKz8dET\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nMIIFUjCCAzqgAwIBAgIQFwNmpFLpQLWUtRrCdyrn0TANBgkqhkiG9w0BAQsFADAm\nMSQwIgYDVQQDExtjdW11bHVzLXRlc3QtY2VydC5zcHZlc3Qubm8wHhcNMTkwMjAx\nMTUzNjMxWhcNMTkwMzAxMTU0NjMxWjAmMSQwIgYDVQQDExtjdW11bHVzLXRlc3Qt\nY2VydC5zcHZlc3Qubm8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCv\nOy4KydxUOW6KmMhq01IAu5Rz47U1oE6ewq0Yi5ea9CrGN7eUWLOogapoKmFFhO2s\n5SDdPt9HOkDNvh75k4B7OFhM+GaOTRubXgPEg8PV7dFFS52+3C0xORdS+wvgI2i9\neIMqbr1Y8Znw5H3pLG8DsU6Q8FCo14mvW8/ou+xKbSOzWFFaP+dNHFBCARqI+DhQ\nYJFkeg4vPd+nFGxfPH/lbbR9WN0tChOTVUJlGkJlht9/0bsVmM8xAdUS/zQ6qK8n\nKWhLpCtWyo8zKDWg5gsdcMoWYgAIXpinc1NcOyGlMv263Zhw7gB+y7JEMK2Ro3e3\nSmhSpH48CkejpIsUOBNnvr514wkLNLet9sXGZvFXs7oiTkUzgu0MFsZPVAkiYhdH\ndYdg2I9e5t4yyxbu+DSr/OvRbUtC9PrO1ncJaO7p9QcXVuRNi2wxLDeaTZgd9S6M\n2fzR2xcwq3Fxk53gDlRTXgqIM/VCPA+3vp5di+MKGK7aLyNRPxeKcsDLEPHF7MeF\nZJw21xTupEMl8w5KaBd5NiKAwxbLyV8YCZFjJG3V2MOxVAA01BAm7w3lz1/iMbKi\nPGbDA0p3cxvaLYs0RdcNfZ6+4X7al7vBXj8+Hwf/tADY648eBEjTqctVDirElCmj\nN8A0ysqldwqCr+8F8k8PUfR3yb809m8QURE7mEAPVQIDAQABo3wwejAOBgNVHQ8B\nAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\nAwIwHwYDVR0jBBgwFoAUlJOHnXHhHeY+AjaPPmKFVRw3K1MwHQYDVR0OBBYEFJST\nh51x4R3mPgI2jz5ihVUcNytTMA0GCSqGSIb3DQEBCwUAA4ICAQAn/chFtfLEebP5\n5Tmb+H+eEzOXaHRonUsVriV/66htOeffkNX2b2DOIosvSwKukOkVggLFmyMKhxiq\neZkkAYyMMjjtWqbkCwoCyb8iDUQLaEovy4Pzwpm3YMVK9+o6cIf4zs3AgzaSSpbo\npq8HQbmFGrUGNEyGMclvf5VL1vCw+0jLpJ1+9b79DRY7puPG19zwWWcHk2hNV3aD\n6lWar7/pjqA9ESQhDTeUsXaFMGVm0Ez97IDI/ZVO+ia5+rIo5wAcUGKuYLIs57Wl\ndhlzMil3mz2g4STiWI+VhtPnqPot6MaWuKIN4R+kJocN365WJf2wozYgEjNFANK+\n3hO396cieWBTqyoYYZRxDxz7slD5NikixrJd50QshYCzqKiNopKsafqMHqc3JKZu\nz9tBZ25g43vdSuAwxjSab5DyYGF3Z447jdKOLUYReNnoB7nlTuW5LYfOX20F/XtC\n+4iL+IDjtAfwATruKzbLnKL9IoemLs7XMoW2qYBmCAcfHrI2F3alAar2XTA9lkDR\nMPpJf9q3VzxkPhjlvi8RPJfWLD1Kw4gMVfhao/NQv3SlhQ2rBpczP8XQOWdTNWp/\n043EPQis8+56AEHis/5+NKoNcQYZJwu2uwK0fdILcStJXR//EI04zBzWo/ULe5nc\nU0GaEMA+K/ZUHV2BxSMA3Br0IwdNvg==\n-----END CERTIFICATE-----\n"
	pemCertPubOnly = "-----BEGIN CERTIFICATE-----\nMIIFUjCCAzqgAwIBAgIQFwNmpFLpQLWUtRrCdyrn0TANBgkqhkiG9w0BAQsFADAm\nMSQwIgYDVQQDExtjdW11bHVzLXRlc3QtY2VydC5zcHZlc3Qubm8wHhcNMTkwMjAx\nMTUzNjMxWhcNMTkwMzAxMTU0NjMxWjAmMSQwIgYDVQQDExtjdW11bHVzLXRlc3Qt\nY2VydC5zcHZlc3Qubm8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCv\nOy4KydxUOW6KmMhq01IAu5Rz47U1oE6ewq0Yi5ea9CrGN7eUWLOogapoKmFFhO2s\n5SDdPt9HOkDNvh75k4B7OFhM+GaOTRubXgPEg8PV7dFFS52+3C0xORdS+wvgI2i9\neIMqbr1Y8Znw5H3pLG8DsU6Q8FCo14mvW8/ou+xKbSOzWFFaP+dNHFBCARqI+DhQ\nYJFkeg4vPd+nFGxfPH/lbbR9WN0tChOTVUJlGkJlht9/0bsVmM8xAdUS/zQ6qK8n\nKWhLpCtWyo8zKDWg5gsdcMoWYgAIXpinc1NcOyGlMv263Zhw7gB+y7JEMK2Ro3e3\nSmhSpH48CkejpIsUOBNnvr514wkLNLet9sXGZvFXs7oiTkUzgu0MFsZPVAkiYhdH\ndYdg2I9e5t4yyxbu+DSr/OvRbUtC9PrO1ncJaO7p9QcXVuRNi2wxLDeaTZgd9S6M\n2fzR2xcwq3Fxk53gDlRTXgqIM/VCPA+3vp5di+MKGK7aLyNRPxeKcsDLEPHF7MeF\nZJw21xTupEMl8w5KaBd5NiKAwxbLyV8YCZFjJG3V2MOxVAA01BAm7w3lz1/iMbKi\nPGbDA0p3cxvaLYs0RdcNfZ6+4X7al7vBXj8+Hwf/tADY648eBEjTqctVDirElCmj\nN8A0ysqldwqCr+8F8k8PUfR3yb809m8QURE7mEAPVQIDAQABo3wwejAOBgNVHQ8B\nAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\nAwIwHwYDVR0jBBgwFoAUlJOHnXHhHeY+AjaPPmKFVRw3K1MwHQYDVR0OBBYEFJST\nh51x4R3mPgI2jz5ihVUcNytTMA0GCSqGSIb3DQEBCwUAA4ICAQAn/chFtfLEebP5\n5Tmb+H+eEzOXaHRonUsVriV/66htOeffkNX2b2DOIosvSwKukOkVggLFmyMKhxiq\neZkkAYyMMjjtWqbkCwoCyb8iDUQLaEovy4Pzwpm3YMVK9+o6cIf4zs3AgzaSSpbo\npq8HQbmFGrUGNEyGMclvf5VL1vCw+0jLpJ1+9b79DRY7puPG19zwWWcHk2hNV3aD\n6lWar7/pjqA9ESQhDTeUsXaFMGVm0Ez97IDI/ZVO+ia5+rIo5wAcUGKuYLIs57Wl\ndhlzMil3mz2g4STiWI+VhtPnqPot6MaWuKIN4R+kJocN365WJf2wozYgEjNFANK+\n3hO396cieWBTqyoYYZRxDxz7slD5NikixrJd50QshYCzqKiNopKsafqMHqc3JKZu\nz9tBZ25g43vdSuAwxjSab5DyYGF3Z447jdKOLUYReNnoB7nlTuW5LYfOX20F/XtC\n+4iL+IDjtAfwATruKzbLnKL9IoemLs7XMoW2qYBmCAcfHrI2F3alAar2XTA9lkDR\nMPpJf9q3VzxkPhjlvi8RPJfWLD1Kw4gMVfhao/NQv3SlhQ2rBpczP8XQOWdTNWp/\n043EPQis8+56AEHis/5+NKoNcQYZJwu2uwK0fdILcStJXR//EI04zBzWo/ULe5nc\nU0GaEMA+K/ZUHV2BxSMA3Br0IwdNvg==\n-----END CERTIFICATE-----\n"
	pfxCert        = "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\nliTAWf5P52EgBAhjHqtjwlzsUQICCAA="
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
func (f *fakeVaultService) GetCertificate(secret *akv.AzureKeyVault, options *vault.CertificateOptions) (*vault.Certificate, error) {
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
	values, err := handler.HandleSecret()
	if err != nil {
		t.Error(err)
	}
	if len(values) != 2 {
		t.Errorf("number of values returned should be 2 but were %d", len(values))
	}

	valuesCM, err := handler.HandleConfigMap()
	if err != nil {
		t.Error(err)
	}
	if len(valuesCM) != 2 {
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
	values, err := handler.HandleSecret()
	if err == nil {
		t.Error("Should fail when no datakey is spesified")
	}
	if values != nil {
		t.Error("handler should not have returned values")
	}
}

func TestHandleConfigMapWithNoDataKey(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: "Some very secret data",
	}

	secret := secret()
	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)
	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.HandleConfigMap()
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
	values, err := handler.HandleSecret()
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
	_, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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
	values, err := handler.HandleSecret()
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

func TestHandleSecretWithTypeTLSAsOutput(t *testing.T) {
	fakeVault := &fakeVaultService{
		fakeSecretValue: pfxCert,
	}

	secret := secret()
	secret.Spec.Vault.Object.Type = "secret"
	secret.Spec.Output.Secret.Type = corev1.SecretTypeTLS

	transformator, err := transformers.CreateTransformator(&secret.Spec.Output)
	handler := NewAzureSecretHandler(secret, fakeVault, *transformator)
	values, err := handler.HandleSecret()
	if err != nil {
		t.Error(err)
	}
	if values == nil {
		t.Error("handler should have returned values")
	}
	if len(values) != 2 {
		t.Error("there should be exactly two key/value pairs present")
	}
	if values[corev1.TLSCertKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.TLSCertKey)
	}
	if values[corev1.TLSPrivateKeyKey] == nil {
		t.Errorf("there should be a value stored for key '%s'", corev1.TLSPrivateKeyKey)
	}
}
