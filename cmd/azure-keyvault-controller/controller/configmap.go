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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"

	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2alpha1"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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

func (c *Controller) getConfigMap(key string) (*corev1.ConfigMap, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	log.Debugf("getting configmap %s from namespace %s", name, namespace)
	cm, err := c.configMapsLister.ConfigMaps(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return cm, err
}

func (c *Controller) getOrCreateKubernetesConfigMap(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (*corev1.ConfigMap, error) {
	var cm *corev1.ConfigMap
	var cmValues map[string]string
	var err error

	cmName := azureKeyVaultSecret.Spec.Output.ConfigMap.Name
	if cmName == "" {
		return nil, fmt.Errorf("output configmap name must be specified using spec.output.configMap.name")
	}

	log.Debugf("get or create configmap %s in namespace %s", cmName, azureKeyVaultSecret.Namespace)
	if cm, err = c.configMapsLister.ConfigMaps(azureKeyVaultSecret.Namespace).Get(cmName); err != nil {
		if errors.IsNotFound(err) {
			cmValues, err = c.getConfigMapFromKeyVault(azureKeyVaultSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to get configmap from azure key vault for configmap '%s'/'%s', error: %+v", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, err)
			}

			if cm, err = c.kubeclientset.CoreV1().ConfigMaps(azureKeyVaultSecret.Namespace).Create(createNewConfigMap(azureKeyVaultSecret, cmValues)); err != nil {
				return nil, err
			}

			log.Infof("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
			if err = c.updateAzureKeyVaultSecretStatusForConfigMap(azureKeyVaultSecret, getMD5HashForConfigMapValues(cmValues)); err != nil {
				return nil, err
			}

			return cm, nil
		}
	}

	if cmName != cm.Name {
		// Name of configmap has changed in AzureKeyVaultSecret, so we need to delete current configmap and recreate
		// under new name

		// Delete configmap
		if err = c.kubeclientset.CoreV1().ConfigMaps(azureKeyVaultSecret.Namespace).Delete(cm.Name, nil); err != nil {
			return nil, err
		}

		// Recreate configmap under new Name
		if cm, err = c.kubeclientset.CoreV1().ConfigMaps(azureKeyVaultSecret.Namespace).Create(createNewConfigMap(azureKeyVaultSecret, cmValues)); err != nil {
			return nil, err
		}
		return cm, nil
	}

	if hasAzureKeyVaultSecretChangedForConfigMap(azureKeyVaultSecret, cm) {
		log.Infof("AzureKeyVaultSecret %s/%s output.secret values has changed and requires update to Secret %s", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, cmName)
		cm, err = c.kubeclientset.CoreV1().ConfigMaps(azureKeyVaultSecret.Namespace).Update(createNewConfigMap(azureKeyVaultSecret, cm.Data))
	}

	return cm, err
}

// createNewConfigMap creates a new ConfigMap for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewConfigMap(azureKeyVaultSecret *akv.AzureKeyVaultSecret, azureSecretValue map[string]string) *corev1.ConfigMap {
	cmName := determineSecretName(azureKeyVaultSecret)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cmName,
			Namespace:   azureKeyVaultSecret.Namespace,
			Labels:      azureKeyVaultSecret.Labels,
			Annotations: azureKeyVaultSecret.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(azureKeyVaultSecret, schema.GroupVersionKind{
					Group:   akv.SchemeGroupVersion.Group,
					Version: akv.SchemeGroupVersion.Version,
					Kind:    "AzureKeyVaultSecret",
				}),
			},
		},
		Data: azureSecretValue,
	}
}

func determineConfigMapName(azureKeyVaultSecret *akv.AzureKeyVaultSecret) string {
	name := azureKeyVaultSecret.Spec.Output.ConfigMap.Name
	if name == "" {
		name = azureKeyVaultSecret.Name
	}
	return name
}

func getMD5HashForConfigMapValues(values map[string]string) string {
	var mergedValues bytes.Buffer

	keys := sortValueKeysForConfigMap(values)

	for _, k := range keys {
		mergedValues.WriteString(k + values[k])
	}

	hasher := md5.New()
	hasher.Write([]byte(mergedValues.String()))
	return hex.EncodeToString(hasher.Sum(nil))
}

func sortValueKeysForConfigMap(values map[string]string) []string {
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func handleConfigMapError(err error, key string) bool {
	log.Debugf("Handling error for '%s' in ConfigMap: %s", key, err.Error())
	if err != nil {
		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			log.Debugf("Error for '%s' was 'Not Found'", key)

			utilruntime.HandleError(fmt.Errorf("ConfigMap '%s' in work queue no longer exists", key))
			return true
		}
	}
	return false
}
