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
	"kmodules.xyz/client-go/tools/queue"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
)

func (c *Controller) initSecret() {
	c.secretInformerFactory.Core().V1().Secrets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if secret, ok := obj.(*corev1.Secret); ok {
				log.Debugf("Secret %s/%s controlled by AzureKeyVaultSecret added. Adding to queue.", secret.Namespace, secret.Name)
				c.enqueueSecret(obj)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			if newSecret, ok := new.(*corev1.Secret); ok {
				oldSecret := old.(*corev1.Secret)

				if newSecret.ResourceVersion == oldSecret.ResourceVersion {
					// Periodic resync will send update events for all known Secrets.
					// Two different versions of the same Secret will always have different RVs.
					return
				}
				secret := new.(*corev1.Secret)
				log.Debugf("Secret %s/%s controlled by AzureKeyVaultSecret changed. Handling.", secret.Namespace, secret.Name)
				c.enqueueSecret(new)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if secret, ok := obj.(*corev1.Secret); ok {
				log.Debugf("Secret %s/%s controlled by AzureKeyVaultSecret deleted. Handling.", secret.Namespace, secret.Name)
				c.enqueueSecret(obj)
			}
		},
	})

}

func (c *Controller) enqueueSecret(obj interface{}) {
	azureKeyVaultSecret, ignore, err := c.getAzureKeyVaultSecretFromSecret(obj)

	if err != nil {
		utilruntime.HandleError(err)
	}

	if !ignore {
		queue.Enqueue(c.akvsCrdQueue.GetQueue(), azureKeyVaultSecret)
	}
}

func (c *Controller) getSecret(key string) (*corev1.Secret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	log.Debugf("Getting Secret %s from namespace %s", name, namespace)
	secret, err := c.secretsLister.Secrets(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return secret, err
}

func (c *Controller) getOrCreateKubernetesSecret(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (*corev1.Secret, error) {
	var secret *corev1.Secret
	var secretValues map[string][]byte
	var err error

	secretName := azureKeyVaultSecret.Spec.Output.Secret.Name
	if secretName == "" {
		return nil, fmt.Errorf("output secret name must be specified using spec.output.secret.name")
	}

	log.Infof("Get or create secret %s in namespace %s", secretName, azureKeyVaultSecret.Namespace)
	if secret, err = c.secretsLister.Secrets(azureKeyVaultSecret.Namespace).Get(secretName); err != nil {
		if errors.IsNotFound(err) {
			secretValues, err = c.getSecretFromKeyVault(azureKeyVaultSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret from Azure Key Vault for secret '%s'/'%s', error: %+v", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, err)
			}

			if secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(createNewSecret(azureKeyVaultSecret, secretValues)); err != nil {
				return nil, err
			}

			log.Infof("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
			if err = c.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, getMD5Hash(secretValues)); err != nil {
				return nil, err
			}

			return secret, nil
		}
	}

	if secretName != secret.Name {
		// Name of secret has changed in AzureKeyVaultSecret, so we need to delete current Secret and recreate
		// under new name

		// Delete secret
		if err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Delete(secret.Name, nil); err != nil {
			return nil, err
		}

		// Recreate secret under new Name
		if secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(createNewSecret(azureKeyVaultSecret, secretValues)); err != nil {
			return nil, err
		}
		return secret, nil
	}

	if hasAzureKeyVaultSecretChanged(azureKeyVaultSecret, secret) {
		log.Infof("AzureKeyVaultSecret %s/%s output.secret values has changed and requires update to Secret %s", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, secretName)
		secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Update(createNewSecret(azureKeyVaultSecret, secret.Data))
	}

	return secret, err
}

func (c *Controller) getAzureKeyVaultSecretFromSecret(obj interface{}) (*akv.AzureKeyVaultSecret, bool, error) {
	var object metav1.Object
	var ok bool

	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, false, fmt.Errorf("error decoding object, invalid type")
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			return nil, false, fmt.Errorf("error decoding object tombstone, invalid type")
		}
		log.Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}

	log.Debugf("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a AzureKeyVaultSecret, we should not do anything more
		// with it.
		if ownerRef.Kind != "AzureKeyVaultSecret" {
			return nil, true, nil
		}

		azureKeyVaultSecret, err := c.azureKeyVaultSecretLister.AzureKeyVaultSecrets(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			log.Infof("ignoring orphaned object '%s' of azureKeyVaultSecret '%s'", object.GetSelfLink(), ownerRef.Name)
			return nil, true, nil
		}

		return azureKeyVaultSecret, false, nil
	}
	return nil, true, nil
}

// newSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewSecret(azureKeyVaultSecret *akv.AzureKeyVaultSecret, azureSecretValue map[string][]byte) *corev1.Secret {
	secretName := determineSecretName(azureKeyVaultSecret)
	secretType := determineSecretType(azureKeyVaultSecret)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
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
		Type: secretType,
		Data: azureSecretValue,
	}
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

func getMD5Hash(values map[string][]byte) string {
	var mergedValues bytes.Buffer

	keys := sortValueKeys(values)

	for _, k := range keys {
		mergedValues.WriteString(k + string(values[k]))
	}

	hasher := md5.New()
	hasher.Write([]byte(mergedValues.String()))
	return hex.EncodeToString(hasher.Sum(nil))
}

func sortValueKeys(values map[string][]byte) []string {
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func handleSecretError(err error, key string) bool {
	log.Debugf("Handling error for '%s' in Secret: %s", key, err.Error())
	if err != nil {
		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			log.Debugf("Error for '%s' was 'Not Found'", key)

			utilruntime.HandleError(fmt.Errorf("Secret '%s' in work queue no longer exists", key))
			return true
		}
	}
	return false
}
