/*
Copyright Sparebanken Vest

Based on the Kubernetes controller example at
https://github.com/kubernetes/sample-controller

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
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"

	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (c *Controller) getSecret(ns, name string) (*corev1.Secret, error) {
	klog.V(4).InfoS("getting secret", "secret", klog.KRef(ns, name))
	secret, err := c.secretsLister.Secrets(ns).Get(name)

	if err != nil {
		return nil, err
	}
	return secret, err
}

func (c *Controller) deleteKubernetesSecretValues(akvs *akv.AzureKeyVaultSecret) error {
	secret, err := c.getSecret(akvs.Namespace, akvs.Spec.Output.Secret.Name)
	if errors.IsNotFound(err) {
		return nil
	}

	secretData := secret.Data

	data, err := c.getSecretFromKeyVault(akvs)
	if err != nil {
		return err
	}

	for key := range data {
		delete(secretData, key)
	}

	newSecret, err := createNewSecretFromExistingWithUpdatedValues(akvs, secretData, secret)
	if err != nil {
		return err
	}

	_, err = c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Update(context.TODO(), newSecret, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) getOrCreateKubernetesSecret(akvs *akv.AzureKeyVaultSecret) (*corev1.Secret, error) {
	var secret *corev1.Secret
	var secretValues map[string][]byte
	var err error

	secretName := akvs.Spec.Output.Secret.Name
	if secretName == "" {
		return nil, fmt.Errorf("output secret name must be specified using spec.output.secret.name")
	}

	klog.V(4).InfoS("get or create secret", "secret", klog.KRef(akvs.Namespace, secretName))
	if secret, err = c.secretsLister.Secrets(akvs.Namespace).Get(secretName); err != nil {
		if errors.IsNotFound(err) {
			secretValues, err = c.getSecretFromKeyVault(akvs)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret from Azure Key Vault for secret '%s'/'%s', error: %+v", akvs.Namespace, akvs.Name, err)
			}

			if secret, err = c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Create(context.TODO(), createNewSecret(akvs, secretValues), metav1.CreateOptions{}); err != nil {
				return nil, err
			}

			klog.InfoS("updating status for azurekeyvaultsecret", "azurekeyvaultsecret", klog.KObj(akvs))
			if err = c.updateAzureKeyVaultSecretStatusForSecret(akvs, getMD5HashOfByteValues(secretValues)); err != nil {
				return nil, err
			}

			return secret, nil
		}
	}

	// get updated secret values from azure key vault
	secretValues, err = c.getSecretFromKeyVault(akvs)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from Azure Key Vault for secret '%s'/'%s', error: %+v", akvs.Namespace, akvs.Name, err)
	}

	if secretName != secret.Name {
		// Name of secret has changed in AzureKeyVaultSecret, so we need to delete current Secret and recreate
		// under new name

		// Only delete if this akvs is the only owner
		if !hasMultipleOwners(secret.GetOwnerReferences()) {
			// Delete secret
			if err = c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
		}

		// Recreate secret under new Name
		if secret, err = c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Create(context.TODO(), createNewSecret(akvs, secretValues), metav1.CreateOptions{}); err != nil {
			return nil, err
		}
		return secret, nil
	}

	if hasAzureKeyVaultSecretChangedForSecret(akvs, secretValues, secret) {
		klog.InfoS("values have changed requiring update to secret", "azurekeyvaultsecret", klog.KObj(akvs), "secret", klog.KObj(secret))

		updatedSecret, err := createNewSecretFromExisting(akvs, secretValues, secret)
		if err != nil {
			return nil, err
		}
		secret, err = c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Update(context.TODO(), updatedSecret, metav1.UpdateOptions{})
		if err == nil {
			klog.InfoS("secret updated", "azurekeyvaultsecret", klog.KObj(akvs), "secret", klog.KObj(secret))
		}
	}

	return secret, err
}

func hasMultipleOwners(refs []metav1.OwnerReference) bool {
	hits := 0
	for _, ref := range refs {
		if ref.Kind == "AzureKeyVaultSecret" {
			hits = hits + 1
		}
		if hits > 1 {
			return true
		}
	}
	return false
}

// newSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewSecret(akvs *akv.AzureKeyVaultSecret, azureSecretValues map[string][]byte) *corev1.Secret {
	secretName := determineSecretName(akvs)
	secretType := determineSecretType(akvs)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   akvs.Namespace,
			Labels:      akvs.Labels,
			Annotations: akvs.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				*newOwnerRef(akvs, schema.GroupVersionKind{
					Group:   akv.SchemeGroupVersion.Group,
					Version: akv.SchemeGroupVersion.Version,
					Kind:    "AzureKeyVaultSecret",
				}),
			},
		},
		Type: secretType,
		Data: azureSecretValues,
	}
}

// createNewSecretFromExisting creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewSecretFromExisting(akvs *akv.AzureKeyVaultSecret, values map[string][]byte, existingSecret *corev1.Secret) (*corev1.Secret, error) {
	secretName := determineSecretName(akvs)
	secretType := determineSecretType(akvs)

	// if existing secret is not opaque and owned by a different akvs,
	// we cannot update this secret, as none opaque secrets cannot have multiple owners,
	// because they would overrite each others keys
	if existingSecret.Type != corev1.SecretTypeOpaque {
		if !isOwnedBy(existingSecret, akvs) {
			controlledBy := metav1.GetControllerOf(existingSecret)
			if controlledBy != nil {
				return nil, fmt.Errorf("cannot update existing secret %s/%s of type %s controlled by %s, as this azurekeyvaultsecret %s would overwrite keys", existingSecret.Namespace, existingSecret.Name, existingSecret.Type, controlledBy.Name, akvs.Name)
			}
			return nil, fmt.Errorf("cannot update existing secret %s/%s of type %s not controlled by akv2k8s, as this azurekeyvaultsecret %s would overwrite keys", existingSecret.Namespace, existingSecret.Name, existingSecret.Type, akvs.Name)
		}
	}

	secretClone := existingSecret.DeepCopy()
	ownerRefs := secretClone.GetOwnerReferences()

	if !isOwnedBy(existingSecret, akvs) {
		ownerRefs = append(ownerRefs, *newOwnerRef(akvs, schema.GroupVersionKind{
			Group:   akv.SchemeGroupVersion.Group,
			Version: akv.SchemeGroupVersion.Version,
			Kind:    "AzureKeyVaultSecret",
		}))
	}

	mergedValues := mergeValuesWithExistingSecret(values, existingSecret)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secretName,
			Namespace:       akvs.Namespace,
			Labels:          akvs.Labels,
			Annotations:     akvs.Annotations,
			OwnerReferences: ownerRefs,
		},
		Type: secretType,
		Data: mergedValues,
	}, nil
}

// updateExistingSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewSecretFromExistingWithUpdatedValues(akvs *akv.AzureKeyVaultSecret, values map[string][]byte, existingSecret *corev1.Secret) (*corev1.Secret, error) {
	secretName := determineSecretName(akvs)
	secretType := determineSecretType(akvs)

	secretClone := existingSecret.DeepCopy()
	ownerRefs := secretClone.GetOwnerReferences()

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secretName,
			Namespace:       akvs.Namespace,
			Labels:          akvs.Labels,
			Annotations:     akvs.Annotations,
			OwnerReferences: ownerRefs,
		},
		Type: secretType,
		Data: values,
	}, nil
}

func isOwnedBy(obj metav1.Object, owner metav1.Object) bool {
	ownerRefs := obj.GetOwnerReferences()

	for _, ref := range ownerRefs {
		if ref.Kind == "AzureKeyVaultSecret" && ref.Name == owner.GetName() && ref.UID == owner.GetUID() {
			return true
		}
	}
	return false
}

func mergeValuesWithExistingSecret(values map[string][]byte, secret *corev1.Secret) map[string][]byte {
	newValues := make(map[string][]byte)

	// copy existing values into new map
	for k, v := range values {
		newValues[k] = v
	}

	// copy any values from existing secret that does not exist in akvs values
	for key, val := range secret.Data {
		if _, ok := values[key]; !ok {
			newValues[key] = val
		}
	}
	return newValues
}

func determineSecretName(azureKeyVaultSecret *akv.AzureKeyVaultSecret) string {
	name := azureKeyVaultSecret.Spec.Output.Secret.Name
	if name == "" {
		name = azureKeyVaultSecret.Name
	}
	return name
}

func determineSecretType(azureKeyVaultSecret *akv.AzureKeyVaultSecret) corev1.SecretType {
	if azureKeyVaultSecret.Spec.Output.Secret.Type == "" {
		return corev1.SecretTypeOpaque
	}

	return azureKeyVaultSecret.Spec.Output.Secret.Type
}

func getMD5HashOfByteValues(values map[string][]byte) string {
	var mergedValues bytes.Buffer

	// sort keys to make sure hash is consistent
	keys := sortByteValueKeys(values)

	for _, k := range keys {
		mergedValues.WriteString(k + string(values[k]))
	}

	hasher := md5.New()
	hasher.Write(mergedValues.Bytes())
	return hex.EncodeToString(hasher.Sum(nil))
}

func getMD5HashOfSecret(akvsValues map[string][]byte, secret *corev1.Secret) string {
	// filter out only values related to this akvs,
	// as multiple akvs can write to a single secret
	values := filterByteValueKeys(akvsValues, secret.Data)
	return getMD5HashOfByteValues(values)
}

func filterByteValueKeys(akvsValues, secretValues map[string][]byte) map[string][]byte {
	filtered := make(map[string][]byte)

	for key := range akvsValues {
		if secretVal, ok := secretValues[key]; ok {
			filtered[key] = secretVal
		}
	}
	return filtered
}

func sortByteValueKeys(values map[string][]byte) []string {
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// func handleSecretError(err error, key string) bool {
// 	if err != nil {
// 		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
// 		if errors.IsNotFound(err) {
// 			log.Debugf("Error for '%s' was 'Not Found'", key)

// 			utilruntime.HandleError(fmt.Errorf("Secret '%s' in work queue no longer exists", key))
// 			return true
// 		}
// 	}
// 	return false
// }
