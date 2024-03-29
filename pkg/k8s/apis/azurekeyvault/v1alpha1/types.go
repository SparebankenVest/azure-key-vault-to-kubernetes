/*
Copyright 2017 The Kubernetes Authors.

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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=akvs,categories=all
// +kubebuilder:printcolumn:name="Vault",type=string,JSONPath=`.spec.vault.name`,description="Which Azure Key Vault this resource is associated with"
// +kubebuilder:printcolumn:name="Vault Object",type=string,JSONPath=`.spec.vault.object.name`,description="Which Azure Key Vault object this resource is associated with"
// +kubebuilder:printcolumn:name="Output Object",type=string,JSONPath=`.status.secretName`,description="Which Kubernetes Secret this resource is synched with, if any"
// +kubebuilder:printcolumn:name="Synched",type=date,JSONPath=`.status.lastAzureUpdate`,description="When this resource was last synched with Azure Key Vault"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="Time since this resource was created"

// AzureKeyVaultSecret is a specification for a AzureKeyVaultSecret resource
// +kubebuilder:subresource:status
type AzureKeyVaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureKeyVaultSecretSpec   `json:"spec"`
	Status AzureKeyVaultSecretStatus `json:"status,omitempty"`
}

// AzureKeyVaultSecretSpec is the spec for a AzureKeyVaultSecret resource
type AzureKeyVaultSecretSpec struct {
	Vault  AzureKeyVault       `json:"vault"`
	Output AzureKeyVaultOutput `json:"output,omitempty"`
}

// AzureKeyVault contains information needed to get the
// Azure Key Vault secret from Azure Key Vault
type AzureKeyVault struct {
	// Name of the Azure Key Vault
	Name   string              `json:"name"`
	Object AzureKeyVaultObject `json:"object"`
}

// AzureKeyVaultObject has information about the Azure Key Vault
// object to get from Azure Key Vault
type AzureKeyVaultObject struct {
	// The object name in Azure Key Vault
	Name string                  `json:"name"`
	Type AzureKeyVaultObjectType `json:"type"`
	// +optional
	// The object version in Azure Key Vault
	Version string `json:"version"`
	// +optional
	ContentType AzureKeyVaultObjectContentType `json:"contentType"`
}

// AzureKeyVaultObjectType defines which Object type to get from Azure Key Vault
// +kubebuilder:validation:Enum=secret;certificate;key;multi-key-value-secret
type AzureKeyVaultObjectType string

// AzureKeyVaultObjectContentType defines what content type a secret contains,
// only used when type is multi-key-value-secret
// +kubebuilder:validation:Enum=application/x-json;application/x-yaml
type AzureKeyVaultObjectContentType string

const (
	// AzureKeyVaultObjectTypeSecret - get Secret object type from Azure Key Vault
	AzureKeyVaultObjectTypeSecret AzureKeyVaultObjectType = "secret"

	// AzureKeyVaultObjectTypeMultiKeyValueSecret - get Secret object type from Azure Key Vault containing multiple key/values
	AzureKeyVaultObjectTypeMultiKeyValueSecret = "multi-key-value-secret"

	// AzureKeyVaultObjectTypeCertificate - get Certificate object type from Azure Key Vault
	AzureKeyVaultObjectTypeCertificate = "certificate"

	// AzureKeyVaultObjectTypeKey - get Key object type from Azure Key Vault
	AzureKeyVaultObjectTypeKey = "key"

	// AzureKeyVaultObjectContentTypeJSON - object content is of type application/x-json
	AzureKeyVaultObjectContentTypeJSON AzureKeyVaultObjectContentType = "application/x-json"

	// AzureKeyVaultObjectContentTypeYaml - object content is of type application/x-yaml
	AzureKeyVaultObjectContentTypeYaml = "application/x-yaml"
)

// AzureKeyVaultOutput defines output sources, currently only support Secret
type AzureKeyVaultOutput struct {
	// +optional
	Secret AzureKeyVaultOutputSecret `json:"secret"`
	// +optional
	Transforms []string `json:"transforms,omitempty"`
}

// AzureKeyVaultOutputSecret has information needed to output
// a secret from Azure Key Vault to Kubernetes as a Secret resource
type AzureKeyVaultOutputSecret struct {
	// Name for Kubernetes secret
	Name string `json:"name"`
	// +optional
	// Type of Secret in Kubernetes
	Type corev1.SecretType `json:"type,omitempty"`
	// +optional
	// The key to use in Kubernetes secret when setting the value from Azure Key Vault object data
	DataKey string `json:"dataKey"`
}

// AzureKeyVaultSecretStatus is the status for a AzureKeyVaultSecret resource
type AzureKeyVaultSecretStatus struct {
	SecretHash      string      `json:"secretHash"`
	LastAzureUpdate metav1.Time `json:"lastAzureUpdate,omitempty"`
	SecretName      string      `json:"secretName"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AzureKeyVaultSecretList is a list of AzureKeyVaultSecret resources
type AzureKeyVaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AzureKeyVaultSecret `json:"items"`
}
