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

	corev1 "k8s.io/api/core/v1"
)

func TestValidateSecretType(t *testing.T) {
	tests := []struct {
		secretType string
		expected   bool
	}{
		{
			secretType: string(corev1.SecretTypeOpaque),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeServiceAccountToken),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeBootstrapToken),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeDockercfg),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeDockerConfigJson),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeBasicAuth),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeSSHAuth),
			expected:   true,
		},
		{
			secretType: string(corev1.SecretTypeTLS),
			expected:   true,
		},
		{
			secretType: "opaque",
			expected:   false,
		},
		{
			secretType: "invalid",
			expected:   false,
		},
	}

	for _, test := range tests {
		result := ValidateSecretType(test.secretType)
		if result != test.expected {
			t.Errorf("Expected ValidateSecretType(%s) to be %v, but got %v", test.secretType, test.expected, result)
		}
	}
}
