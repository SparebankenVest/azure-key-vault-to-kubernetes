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

package v2alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=akvs,categories=all
// +kubebuilder:printcolumn:name="Vault",type=string,JSONPath=`.spec.vault.name`,description="Which Azure Key Vault this resource is asosiated with"
// +kubebuilder:printcolumn:name="Vault Object",type=string,JSONPath=`.spec.vault.object.name`,description="Which Azure Key Vault object this resource is asosiated with"
// +kubebuilder:printcolumn:name="Secret Name",type=string,JSONPath=`.status.secretName`,description="Which Kubernetes Secret this resource is synched with, if any"
// +kubebuilder:printcolumn:name="ConfigMap Name",type=string,JSONPath=`.status.configMapName`,description="Which Kubernetes ConfigMap this resource is synched with, if any"
// +kubebuilder:printcolumn:name="Last Synched",type=date,JSONPath=`.status.lastAzureUpdate`,description="When this resource was last synched with Azure Key Vault"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="Time since this resource was created"

// AzureKeyVaultSecret is a specification for a AzureKeyVaultSecret resource
// +kubebuilder:subresource:status
type AzureKeyVaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureKeyVaultSecretSpec   `json:"spec"`
	Status AzureKeyVaultSecretStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AzureKeyVaultSecretList is a list of AzureKeyVaultSecret resources
type AzureKeyVaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AzureKeyVaultSecret `json:"items"`
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
	// +optional
	AzureIdentity AzureIdentity `json:"azureIdentity,omitempty"`
}

// AzureIdentity has information about the azure
// identity used for Azure Key Vault authentication
type AzureIdentity struct {
	// Name of the azureIdentity to use for Azure Key Vault authentication
	Name string `json:"name"`
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

// AzureKeyVaultOutput defines output sources, supports Secret and Configmap
type AzureKeyVaultOutput struct {
	// +optional
	Secret AzureKeyVaultOutputSecret `json:"secret"`
	// +optional
	ConfigMap AzureKeyVaultOutputConfigMap `json:"configMap"`
	// +optional
	Transform []string `json:"transform,omitempty"`
}

// AzureKeyVaultOutputSecret has information needed to output
// a secret from Azure Key Vault to Kubertnetes as a Secret resource
type AzureKeyVaultOutputSecret struct {
	// Name for Kubernetes secret
	Name string `json:"name"`
	// +optional
	// Type of Secret in Kubernetes
	Type corev1.SecretType `json:"type,omitempty"`
	// +optional
	// The key to use in Kubernetes secret when setting the value from Azure Keyv Vault object data
	DataKey string `json:"dataKey,omitempty"`
	// +optional
	// By setting chainOrder to ensureserverfirst the server certificate will be moved first in the chain
	// +kubebuilder:validation:Enum=ensureserverfirst
	ChainOrder string `json:"chainOrder,omitempty"`
}

// AzureKeyVaultOutputConfigMap has information needed to output
// a secret from Azure Key Vault to Kubertnetes as a ConfigMap resource
type AzureKeyVaultOutputConfigMap struct {
	// Name for Kubernetes ConfigMap
	Name string `json:"name"`
	// The key to use in Kubernetes ConfigMap when setting the value from Azure Keyv Vault object data
	DataKey string `json:"dataKey"`
}

// AzureKeyVaultSecretStatus is the status for a AzureKeyVaultSecret resource
type AzureKeyVaultSecretStatus struct {
	SecretHash      string      `json:"secretHash,omitempty"`
	SecretName      string      `json:"secretName,omitempty"`
	ConfigMapHash   string      `json:"configMapHash,omitempty"`
	ConfigMapName   string      `json:"configMapName,omitempty"`
	LastAzureUpdate metav1.Time `json:"lastAzureUpdate,omitempty"`
}
