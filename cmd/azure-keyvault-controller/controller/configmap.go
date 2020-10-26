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
	"k8s.io/client-go/tools/cache"
)

func convertToConfigMap(obj interface{}) (*corev1.ConfigMap, error) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		cm, ok = tombstone.Obj.(*corev1.ConfigMap)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a ConfigMap %#v", obj)
		}
	}
	return cm, nil
}

func (c *Controller) getConfigMapByKey(key string) (*corev1.ConfigMap, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}
	return c.getConfigMap(namespace, name)
}

func (c *Controller) getConfigMap(ns, name string) (*corev1.ConfigMap, error) {
	klog.V(4).InfoS("getting configmap", "configmap", klog.KRef(ns, name))
	cm, err := c.configMapsLister.ConfigMaps(ns).Get(name)

	if err != nil {
		return nil, err
	}
	return cm, err
}

func (c *Controller) deleteKubernetesConfigMapValues(akvs *akv.AzureKeyVaultSecret) error {
	cm, err := c.getConfigMap(akvs.Namespace, akvs.Spec.Output.ConfigMap.Name)
	if errors.IsNotFound(err) {
		return nil
	}

	cmData := cm.Data

	data, err := c.getConfigMapFromKeyVault(akvs)
	if err != nil {
		return err
	}

	for key := range data {
		delete(cmData, key)
	}

	newCM, err := createNewConfigMapFromExistingWithUpdatedValues(akvs, cmData, cm)
	if err != nil {
		return err
	}

	cm, err = c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Update(context.TODO(), newCM, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) getOrCreateKubernetesConfigMap(akvs *akv.AzureKeyVaultSecret) (*corev1.ConfigMap, error) {
	var cm *corev1.ConfigMap
	var cmValues map[string]string
	var err error

	cmName := akvs.Spec.Output.ConfigMap.Name
	if cmName == "" {
		return nil, fmt.Errorf("output configmap name must be specified using spec.output.configMap.name")
	}

	klog.V(4).InfoS("get or create configmap", "configmap", klog.KRef(akvs.Namespace, cmName))
	if cm, err = c.configMapsLister.ConfigMaps(akvs.Namespace).Get(cmName); err != nil {
		klog.V(4).ErrorS(err, "failed to get configmap ", "configmap", klog.KRef(akvs.Namespace, cmName))
		if errors.IsNotFound(err) {
			klog.V(4).InfoS("configmap was not found", "configmap", klog.KRef(akvs.Namespace, cmName))
			klog.V(4).InfoS("getting configmap value from azure key vault", "configmap", klog.KRef(akvs.Namespace, cmName))
			cmValues, err = c.getConfigMapFromKeyVault(akvs)
			if err != nil {
				return nil, fmt.Errorf("failed to get configmap from azure key vault for configmap '%s'/'%s', error: %+v", akvs.Namespace, akvs.Name, err)
			}

			if cm, err = c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Create(context.TODO(), createNewConfigMap(akvs, cmValues), metav1.CreateOptions{}); err != nil {
				return nil, fmt.Errorf("failed to create new configmap, err: %+v", err)
			}

			klog.V(2).InfoS("updating status for azurekeyvaultsecret", "azurekeyvaultsecret", klog.KObj(akvs))
			if err = c.updateAzureKeyVaultSecretStatusForConfigMap(akvs, getMD5HashOfStringValues(cmValues)); err != nil {
				return nil, fmt.Errorf("failed to update status for azurekeyvaultsecret %s, error: %+v", akvs.Name, err)
			}

			return cm, nil
		}
	}

	// get updated secret values from azure key vault
	klog.V(4).InfoS("getting secret from azure key vault", "azurekeyvaultsecret", klog.KObj(akvs))
	cmValues, err = c.getConfigMapFromKeyVault(akvs)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from Azure Key Vault for secret '%s'/'%s', error: %+v", akvs.Namespace, akvs.Name, err)
	}

	if cmName != cm.Name {
		// Name of configmap has changed in AzureKeyVaultSecret, so we need to delete current configmap and recreate
		// under new name

		// Only delete if this akvs is the only owner
		if !hasMultipleOwners(cm.GetOwnerReferences()) {
			// Delete configmap
			if err = c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Delete(context.TODO(), cm.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
		}
		// Recreate configmap under new Name
		if cm, err = c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Create(context.TODO(), createNewConfigMap(akvs, cmValues), metav1.CreateOptions{}); err != nil {
			return nil, err
		}
		return cm, nil
	}

	if hasAzureKeyVaultSecretChangedForConfigMap(akvs, cmValues, cm) {
		klog.V(2).InfoS("values have changed requiring update to configmap", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KObj(cm))

		updatedCM, err := createNewConfigMapFromExisting(akvs, cmValues, cm)
		if err != nil {
			return nil, err
		}

		cm, err = c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Update(context.TODO(), updatedCM, metav1.UpdateOptions{})
		if err == nil {
			klog.V(2).InfoS("configmap updated", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KObj(cm))
		}
	}

	return cm, err
}

// createNewConfigMap creates a new ConfigMap for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewConfigMap(azureKeyVaultSecret *akv.AzureKeyVaultSecret, azureSecretValue map[string]string) *corev1.ConfigMap {
	cmName := determineConfigMapName(azureKeyVaultSecret)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cmName,
			Namespace:   azureKeyVaultSecret.Namespace,
			Labels:      azureKeyVaultSecret.Labels,
			Annotations: azureKeyVaultSecret.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				*newOwnerRef(azureKeyVaultSecret, schema.GroupVersionKind{
					Group:   akv.SchemeGroupVersion.Group,
					Version: akv.SchemeGroupVersion.Version,
					Kind:    "AzureKeyVaultSecret",
				}),
			},
		},
		Data: azureSecretValue,
	}
}

func newOwnerRef(owner metav1.Object, gvk schema.GroupVersionKind) *metav1.OwnerReference {
	blockOwnerDeletion := true
	isController := false
	return &metav1.OwnerReference{
		APIVersion:         gvk.GroupVersion().String(),
		Kind:               gvk.Kind,
		Name:               owner.GetName(),
		UID:                owner.GetUID(),
		BlockOwnerDeletion: &blockOwnerDeletion,
		Controller:         &isController,
	}
}

// updateExistingSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewConfigMapFromExisting(akvs *akv.AzureKeyVaultSecret, values map[string]string, existingCM *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	cmName := determineConfigMapName(akvs)
	cmClone := existingCM.DeepCopy()
	ownerRefs := cmClone.GetOwnerReferences()

	if !isOwnedBy(existingCM, akvs) {
		ownerRefs = append(ownerRefs, *newOwnerRef(akvs, schema.GroupVersionKind{
			Group:   akv.SchemeGroupVersion.Group,
			Version: akv.SchemeGroupVersion.Version,
			Kind:    "AzureKeyVaultSecret",
		}))
	}

	mergedValues := mergeValuesWithExistingConfigMap(values, existingCM)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            cmName,
			Namespace:       akvs.Namespace,
			Labels:          akvs.Labels,
			Annotations:     akvs.Annotations,
			OwnerReferences: ownerRefs,
		},
		Data: mergedValues,
	}, nil
}

// updateExistingSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewConfigMapFromExistingWithUpdatedValues(akvs *akv.AzureKeyVaultSecret, values map[string]string, existingCM *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	cmName := determineConfigMapName(akvs)
	cmClone := existingCM.DeepCopy()
	ownerRefs := cmClone.GetOwnerReferences()

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            cmName,
			Namespace:       akvs.Namespace,
			Labels:          akvs.Labels,
			Annotations:     akvs.Annotations,
			OwnerReferences: ownerRefs,
		},
		Data: values,
	}, nil
}

func mergeValuesWithExistingConfigMap(values map[string]string, cm *corev1.ConfigMap) map[string]string {
	newValues := make(map[string]string)

	// copy existing values into new map
	for k, v := range values {
		newValues[k] = v
	}

	// copy any values from existing secret that does not exist in akvs values
	for key, val := range cm.Data {
		if _, ok := values[key]; !ok {
			newValues[key] = val
		}
	}
	return newValues
}

func determineConfigMapName(azureKeyVaultSecret *akv.AzureKeyVaultSecret) string {
	name := azureKeyVaultSecret.Spec.Output.ConfigMap.Name
	if name == "" {
		name = azureKeyVaultSecret.Name
	}
	return name
}

func getMD5HashOfStringValues(values map[string]string) string {
	var mergedValues bytes.Buffer

	// sort keys to make sure hash is consistant
	keys := sortStringValueKeys(values)

	for _, k := range keys {
		mergedValues.WriteString(k + values[k])
	}

	hasher := md5.New()
	hasher.Write([]byte(mergedValues.String()))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getMD5HashOfConfigMap(akvsValues map[string]string, cm *corev1.ConfigMap) string {
	// filter out only values related to this akvs,
	// as multiple akvs can write to a single secret
	values := filterStringValueKeys(akvsValues, cm.Data)
	return getMD5HashOfStringValues(values)
}

func filterStringValueKeys(akvsValues, cmValues map[string]string) map[string]string {
	filtered := make(map[string]string)

	for key := range akvsValues {
		if cmVal, ok := cmValues[key]; ok {
			filtered[key] = cmVal
		}
	}
	return filtered
}

func sortStringValueKeys(values map[string]string) []string {
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// func handleConfigMapError(err error, key string) bool {
// 	if err != nil {
// 		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
// 		if errors.IsNotFound(err) {
// 			klog.V(2).InfoS("configmap in work queue no longer exists", "key", key)
// 			return true
// 		}
// 	}
// 	return false
// }
