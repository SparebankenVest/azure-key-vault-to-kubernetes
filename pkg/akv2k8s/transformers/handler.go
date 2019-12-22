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

package transformers

import (
	"encoding/base64"
	akvsv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	"strings"
)

// TransformSecret will iterate over all enabled transformers (if any), run each transformer and return transformed result
func TransformSecret(spec *akvsv1alpha1.AzureKeyVaultOutput, secret string) string {
	return ""
}

// TransformationHandler handles transformation of Azure Key Vault data
type TransformationHandler interface {
	Handle() (string, error)
}

// Base64DecodeHandler handles base64 decoding of data
type Base64DecodeHandler struct {
	secret string
}

// TrimHandler handles standar trimming of string data
type TrimHandler struct {
	secret string
}

// NewBase64DecodeHandler creates a new handler for decoding base64 data
func NewBase64DecodeHandler(secret string) *Base64DecodeHandler {
	return &Base64DecodeHandler{
		secret: secret,
	}
}

// NewTrimHandler creates a new handler for trimming empty spaces from a secret
func NewTrimHandler(secret string) *TrimHandler {
	return &TrimHandler{
		secret: secret,
	}
}

// Handle handles decoding of base64 encoded data
func (h *Base64DecodeHandler) Handle() (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(h.secret)

	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// Handle handles trimming empty spaces from secret
func (h *TrimHandler) Handle() (string, error) {
	return strings.TrimSpace(h.secret), nil
}
