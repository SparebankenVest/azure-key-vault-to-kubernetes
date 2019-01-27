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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AzureKeyVaultSecret is a specification for a AzureKeyVaultSecret resource
type AzureKeyVaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AzureKeyVaultSecretSpec `json:"spec"`
	// Status AzureKeyVaultSecretStatus `json:"status"`
}

// AzureKeyVaultSecretSpec is the spec for a AzureKeyVaultSecret resource
type AzureKeyVaultSecretSpec struct {
	Vault        AzureKeyVaultSecretVaultSpec        `json:"vault"`
	OutputSecret AzureKeyVaultSecretOutputSecretSpec `json:"outputSecret"`
}

type AzureKeyVaultSecretVaultSpec struct {
	Name       string `json:"name"`
	ObjectType string `json:"objectType"`
	ObjectName string `json:"objectName"`
}

type AzureKeyVaultSecretOutputSecretSpec struct {
	Name    string `json:"name"`
	KeyName string `json:"keyName"`
}

// // AzureKeyVaultSecretStatus is the status for a AzureKeyVaultSecret resource
// type AzureKeyVaultSecretStatus struct {
// 	AvailableReplicas int32 `json:"availableReplicas"`
// }

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AzureKeyVaultSecretList is a list of AzureKeyVaultSecret resources
type AzureKeyVaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AzureKeyVaultSecret `json:"items"`
}
