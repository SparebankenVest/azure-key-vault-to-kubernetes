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
	"strings"
)

// TransformationHandler handles transformation of Azure Key Vault data
type TransformationHandler interface {
	Handle(string) (string, error)
}

// Base64EncodeHandler handles base64 encoding of data
type Base64EncodeHandler struct{}

// Base64DecodeHandler handles base64 decoding of data
type Base64DecodeHandler struct{}

// TrimHandler handles standar trimming of string data
type TrimHandler struct{}

// Handle encode secrets as a base64 encoded string
func (h *Base64EncodeHandler) Handle(secret string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(secret)), nil
}

// Handle handles decoding of base64 encoded data
func (h *Base64DecodeHandler) Handle(secret string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(secret)

	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// Handle handles trimming empty spaces from secret
func (h *TrimHandler) Handle(secret string) (string, error) {
	return strings.TrimSpace(secret), nil
}
