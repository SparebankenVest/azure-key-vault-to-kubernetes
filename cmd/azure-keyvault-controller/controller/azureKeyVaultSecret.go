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
	"context"
	"fmt"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"kmodules.xyz/client-go/tools/queue"
)

func (c *Controller) initAzureKeyVaultSecret() {
	_, err := c.akvsInformerFactory.AzureKeyVault().V2beta1().AzureKeyVaultSecrets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			akvs, err := convertToAzureKeyVaultSecret(obj)
			if err != nil {
				klog.ErrorS(err, "failed to convert to azurekeyvaultsecret")
				syncFailures.WithLabelValues("add", "AzureKeyVaultSecret").Inc()
				return
			}

			if c.akvsHasOutputDefined(akvs) {
				klog.V(4).InfoS("adding to queue", "azurekeyvaultsecret", klog.KObj(akvs))
				syncCounter.WithLabelValues("add", "AzureKeyVaultSecret").Inc()
				queue.Enqueue(c.akvsCrdQueue.GetQueue(), obj)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			newAkvs, err := convertToAzureKeyVaultSecret(new)
			if err != nil {
				klog.ErrorS(err, "failed to convert to azurekeyvaultsecret")
				syncFailures.WithLabelValues("update", "AzureKeyVault").Inc()
				return
			}

			oldAkvs, err := convertToAzureKeyVaultSecret(old)
			if err != nil {
				klog.ErrorS(err, "failed to convert to azurekeyvaultsecret")
				syncFailures.WithLabelValues("update", "AzureKeyVault").Inc()
				return
			}

			// If akvs has not changed and has secret output, add to akv queue to check if secret has changed in akv
			if newAkvs.ResourceVersion == oldAkvs.ResourceVersion && c.akvsHasOutputDefined(newAkvs) {
				klog.V(4).InfoS("adding to azure key vault queue to check if secret has changed in azure key vault", "azurekeyvaultsecret", klog.KObj(newAkvs))
				syncCounter.WithLabelValues("update", "AzureKeyVault").Inc()
				queue.Enqueue(c.azureKeyVaultQueue.GetQueue(), new)
				return
			}

			if c.akvsHasOutputDefined(newAkvs) || c.akvsHasOutputDefined(oldAkvs) {
				klog.V(4).InfoS("azurekeyvaultsecret changed - adding to queue", "azurekeyvaultsecret", klog.KObj(newAkvs))
				syncCounter.WithLabelValues("update", "AzureKeyVaultSecret").Inc()
				queue.Enqueue(c.akvsCrdQueue.GetQueue(), new)
			}
		},
		DeleteFunc: func(obj interface{}) {
			akvs, err := convertToAzureKeyVaultSecret(obj)
			if err != nil {
				klog.ErrorS(err, "failed to convert to azurekeyvaultsecret")
				syncFailures.WithLabelValues("delete", "AzureKeyVaultSecret").Inc()
				return
			}

			if c.akvsHasOutputDefined(akvs) {
				klog.V(4).InfoS("azurekeyvaultsecret deleted - adding to queue", "azurekeyvaultsecret", klog.KObj(akvs))
				syncCounter.WithLabelValues("delete", "AzureKeyVaultSecret").Inc()
				queue.Enqueue(c.akvsCrdQueue.GetQueue(), obj)

				err = c.deleteKubernetesValues(akvs)
				if err != nil {
					klog.ErrorS(err, "failed to delete secret data from azurekeyvaultsecret", "azurekeyvaultsecret", klog.KObj(akvs))
					syncFailures.WithLabelValues("delete", "AzureKeyVaultSecret").Inc()
				}

				// Getting default key to remove from Azure work queue
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err != nil {
					utilruntime.HandleError(err)
					return
				}
				c.azureKeyVaultQueue.GetQueue().Forget(key)
			}
		},
	})
	if err != nil {
		klog.ErrorS(err, "unable to add event handler")
	}
}

func (c *Controller) syncDeletedAzureKeyVaultSecret(key string) error {
	var akvs *akv.AzureKeyVaultSecret
	var err error

	klog.V(4).InfoS("processing azurekeyvaultsecret", "key", key)
	if akvs, err = c.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	var outputObject metav1.Object
	if c.akvsHasOutputSecret(akvs) {
		secret, err := c.getOrCreateKubernetesSecret(akvs)
		if err != nil {
			return err
		}

		klog.V(4).InfoS("sync successful", "azurekeyvaultsecret", klog.KObj(akvs), "secret", klog.KObj(secret))
		c.recorder.Event(secret, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSynced)
		outputObject = secret
	}

	if c.akvsHasOutputConfigMap(akvs) {
		cm, err := c.getOrCreateKubernetesConfigMap(akvs)
		if err != nil {
			return err
		}

		klog.V(4).InfoS("sync successful", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KObj(cm))
		c.recorder.Event(cm, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSynced)
		outputObject = cm
	}

	if !isOwnedBy(outputObject, akvs) { // checks if the object has a controllerRef set to the given owner
		msg := fmt.Sprintf(MessageResourceExists, outputObject.GetName())
		c.recorder.Event(akvs, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	return nil
}

func (c *Controller) syncAzureKeyVaultSecret(key string) error {
	var akvs *akv.AzureKeyVaultSecret
	var err error

	klog.V(4).InfoS("processing azurekeyvaultsecret", "key", key)
	if akvs, err = c.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	var outputObject metav1.Object
	if c.akvsHasOutputSecret(akvs) {
		secret, err := c.getOrCreateKubernetesSecret(akvs)
		if err != nil {
			return err
		}

		klog.V(4).InfoS("sync successful", "azurekeyvaultsecret", klog.KObj(akvs), "secret", klog.KObj(secret))
		c.recorder.Event(secret, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSynced)
		outputObject = secret
	}

	if c.akvsHasOutputConfigMap(akvs) {
		cm, err := c.getOrCreateKubernetesConfigMap(akvs)
		if err != nil {
			return err
		}

		klog.V(4).InfoS("sync successful", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KObj(cm))
		c.recorder.Event(cm, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSynced)
		outputObject = cm
	}

	if !isOwnedBy(outputObject, akvs) { // checks if the object has a controllerRef set to the given owner
		msg := fmt.Sprintf(MessageResourceExists, outputObject.GetName())
		c.recorder.Event(akvs, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	return nil
}

func (c *Controller) syncAzureKeyVault(key string) error {
	var akvs *akv.AzureKeyVaultSecret
	var err error
	var secretName string
	var cmName string
	var cmHash string
	var secretHash string

	klog.V(4).InfoS("checking state of azurekeyvaultsecret in azure key vault", "key", key)
	if akvs, err = c.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	if c.akvsHasOutputSecret(akvs) {
		klog.V(4).InfoS("getting secret value from azure key vault", "azurekeyvaultsecret", klog.KObj(akvs))
		secretValue, err := c.getSecretFromKeyVault(akvs)
		if err != nil {
			msg := fmt.Sprintf(FailedAzureKeyVault, akvs.Name, akvs.Spec.Vault.Name, err.Error())
			c.recorder.Event(akvs, corev1.EventTypeWarning, ErrAzureVault, msg)
			syncFailures.WithLabelValues("sync", "AzureKeyVault").Inc()
			return fmt.Errorf(msg)
		}

		secretHash = getMD5HashOfByteValues(secretValue)

		klog.V(4).InfoS("checking if secret value has changed in azure", "azurekeyvaultsecret", klog.KObj(akvs))
		if akvs.Status.SecretHash != secretHash {
			klog.V(4).InfoS("value has changed in azure key vault", "before", akvs.Status.SecretHash, "now", secretHash, "azurekeyvaultsecret", klog.KObj(akvs))

			klog.InfoS("updating with recent changes from azure key vault", "azurekeyvaultsecret", klog.KObj(akvs), "secret", klog.KRef(akvs.Namespace, akvs.Spec.Output.Secret.Name))
			existingSecret, err := c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Get(context.TODO(), akvs.Spec.Output.Secret.Name, metav1.GetOptions{})
			if err != nil {
				klog.Infof("existing secret %s not found, creating new secret", akvs.Spec.Output.Secret.Name)
				newSecret := createNewSecret(akvs, secretValue)
				secret, err := c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Create(context.TODO(), newSecret, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create the secret %s, error: %+v", akvs.Spec.Output.Secret.Name, err)
				}

				secretName = secret.Name
				klog.InfoS("secret created", "azurekeyvaultsecret", klog.KObj(akvs), "secret", klog.KObj(secret))
			} else {
				updatedSecret, err := createNewSecretFromExisting(akvs, secretValue, existingSecret)
				if err != nil {
					return fmt.Errorf("failed to update existing secret %s, error: %+v", akvs.Spec.Output.Secret.Name, err)
				}
				secret, err := c.kubeclientset.CoreV1().Secrets(akvs.Namespace).Update(context.TODO(), updatedSecret, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("failed to update secret, error: %+v", err)
				}

				secretName = secret.Name
				klog.InfoS("secret changed - any resources (like pods) using this secret must be restarted to pick up the new value - details: https://github.com/kubernetes/kubernetes/issues/22368", "azurekeyvaultsecret", klog.KObj(secret), "secret", klog.KObj(akvs))
			}
		}
	}

	if c.akvsHasOutputConfigMap(akvs) {
		klog.V(4).InfoS("getting secret value from azure key vault", "azurekeyvaultsecret", klog.KObj(akvs))
		cmValue, err := c.getConfigMapFromKeyVault(akvs)
		if err != nil {
			msg := fmt.Sprintf(FailedAzureKeyVault, akvs.Name, akvs.Spec.Vault.Name, err.Error())
			c.recorder.Event(akvs, corev1.EventTypeWarning, ErrAzureVault, msg)
			return fmt.Errorf(msg)
		}

		cmHash = getMD5HashOfStringValues(cmValue)

		klog.V(4).InfoS("checking if secret value has changed in azure key vault", "azurekeyvaultsecret", klog.KObj(akvs))
		if akvs.Status.ConfigMapHash != cmHash {
			klog.V(4).InfoS("value has changed in azure key vault", "before", akvs.Status.SecretHash, "now", secretHash, "azurekeyvaultsecret", klog.KObj(akvs))

			klog.InfoS("updating with recent changes from azure key vault", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KRef(akvs.Namespace, akvs.Spec.Output.ConfigMap.Name))
			existingCm, err := c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Get(context.TODO(), akvs.Spec.Output.ConfigMap.Name, metav1.GetOptions{})
			if err != nil {
				klog.Infof("existing configmap %s not found, creating new configmap", akvs.Spec.Output.ConfigMap.Name)
				newCm := createNewConfigMap(akvs, cmValue)
				cm, err := c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Create(context.TODO(), newCm, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create the configmap %s, error: %+v", akvs.Spec.Output.ConfigMap.Name, err)
				}
				cmName = cm.Name
				klog.InfoS("configmap created", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KObj(cm))
			} else {
				updatedCm, err := createNewConfigMapFromExisting(akvs, cmValue, existingCm)
				if err != nil {
					return fmt.Errorf("failed to update existing configmap %s, error: %+v", akvs.Spec.Output.ConfigMap.Name, err)
				}
				cm, err := c.kubeclientset.CoreV1().ConfigMaps(akvs.Namespace).Update(context.TODO(), updatedCm, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("failed to update configmap, error: %+v", err)
				}
				cmName = cm.Name
				klog.InfoS("configmap changed - any resources (like pods) using this configmap must be restarted to pick up the new value - details: https://github.com/kubernetes/kubernetes/issues/22368", "azurekeyvaultsecret", klog.KObj(akvs), "configmap", klog.KObj(cm))
			}
		}
	}

	klog.V(4).InfoS("updating status", "azurekeyvaultsecret", klog.KObj(akvs))
	if err = c.updateAzureKeyVaultSecretStatus(akvs, secretName, cmName, secretHash, cmHash); err != nil {
		return err
	}

	klog.V(4).InfoS("sync successful", "azurekeyvaultsecret", klog.KObj(akvs))
	c.recorder.Event(akvs, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSyncedWithAzureKeyVault)
	return nil
}

func (c *Controller) deleteKubernetesValues(akvs *akv.AzureKeyVaultSecret) error {
	if c.akvsHasOutputSecret(akvs) {
		return c.deleteKubernetesSecretValues(akvs)
	}
	if c.akvsHasOutputConfigMap(akvs) {
		return c.deleteKubernetesConfigMapValues(akvs)
	}
	return nil
}

func convertToAzureKeyVaultSecret(obj interface{}) (*akv.AzureKeyVaultSecret, error) {
	secret, ok := obj.(*akv.AzureKeyVaultSecret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		secret, ok = tombstone.Obj.(*akv.AzureKeyVaultSecret)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a AzureKeyVaultSecret %#v", obj)
		}
	}
	return secret, nil
}

func (c *Controller) akvsHasOutputDefined(secret *akv.AzureKeyVaultSecret) bool {
	return c.akvsHasOutputSecret(secret) || c.akvsHasOutputConfigMap(secret)
}

func (c *Controller) akvsHasOutputSecret(secret *akv.AzureKeyVaultSecret) bool {
	return secret.Spec.Output.Secret.Name != ""
}

func (c *Controller) akvsHasOutputConfigMap(secret *akv.AzureKeyVaultSecret) bool {
	return secret.Spec.Output.ConfigMap.Name != ""
}

func (c *Controller) getSecretFromKeyVault(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (map[string][]byte, error) {
	var secretHandler KubernetesHandler

	switch azureKeyVaultSecret.Spec.Vault.Object.Type {
	case akv.AzureKeyVaultObjectTypeSecret:
		transformator, err := transformers.CreateTransformator(&azureKeyVaultSecret.Spec.Output)
		if err != nil {
			return nil, err
		}
		secretHandler = NewAzureSecretHandler(azureKeyVaultSecret, c.vaultService, *transformator)
	case akv.AzureKeyVaultObjectTypeCertificate:
		secretHandler = NewAzureCertificateHandler(azureKeyVaultSecret, c.vaultService)
	case akv.AzureKeyVaultObjectTypeKey:
		secretHandler = NewAzureKeyHandler(azureKeyVaultSecret, c.vaultService)
	case akv.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		secretHandler = NewAzureMultiKeySecretHandler(azureKeyVaultSecret, c.vaultService)
	default:
		return nil, fmt.Errorf("azure key vault object type '%s' not currently supported", azureKeyVaultSecret.Spec.Vault.Object.Type)
	}
	return secretHandler.HandleSecret()
}

func (c *Controller) getConfigMapFromKeyVault(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (map[string]string, error) {
	var cmHandler KubernetesHandler

	switch azureKeyVaultSecret.Spec.Vault.Object.Type {
	case akv.AzureKeyVaultObjectTypeSecret:
		transformator, err := transformers.CreateTransformator(&azureKeyVaultSecret.Spec.Output)
		if err != nil {
			return nil, err
		}
		cmHandler = NewAzureSecretHandler(azureKeyVaultSecret, c.vaultService, *transformator)
	case akv.AzureKeyVaultObjectTypeCertificate:
		cmHandler = NewAzureCertificateHandler(azureKeyVaultSecret, c.vaultService)
	case akv.AzureKeyVaultObjectTypeKey:
		cmHandler = NewAzureKeyHandler(azureKeyVaultSecret, c.vaultService)
	case akv.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		cmHandler = NewAzureMultiKeySecretHandler(azureKeyVaultSecret, c.vaultService)
	default:
		return nil, fmt.Errorf("azure key vault object type '%s' not currently supported", azureKeyVaultSecret.Spec.Vault.Object.Type)
	}
	return cmHandler.HandleConfigMap()
}

func (c *Controller) getAzureKeyVaultSecret(key string) (*akv.AzureKeyVaultSecret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	azureKeyVaultSecret, err := c.azureKeyVaultSecretLister.AzureKeyVaultSecrets(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return azureKeyVaultSecret, err
}

func hasAzureKeyVaultSecretChangedForSecret(akvs *akv.AzureKeyVaultSecret, akvsValues map[string][]byte, secret *corev1.Secret) bool {
	// check if secret type has changed
	secretType := determineSecretType(akvs)
	if secretType != secret.Type {
		return true
	}

	// Check if dataKey has changed by trying to lookup key
	if akvs.Spec.Output.Secret.DataKey != "" {
		if _, ok := secret.Data[akvs.Spec.Output.Secret.DataKey]; !ok {
			return true
		}
	}

	// Check if data content has changed
	if akvs.Status.SecretHash != getMD5HashOfSecret(akvsValues, secret) {
		return true
	}
	return false
}

func hasAzureKeyVaultSecretChangedForConfigMap(akvs *akv.AzureKeyVaultSecret, akvsValues map[string]string, cm *corev1.ConfigMap) bool {
	// Check if dataKey has changed by trying to lookup key
	if akvs.Spec.Output.ConfigMap.DataKey != "" {
		if _, ok := cm.Data[akvs.Spec.Output.ConfigMap.DataKey]; !ok {
			return true
		}
	}

	// Check if data content has changed
	if akvs.Status.ConfigMapHash != getMD5HashOfConfigMap(akvsValues, cm) {
		return true
	}
	return false
}

func (c *Controller) updateAzureKeyVaultSecretStatus(akvs *akv.AzureKeyVaultSecret, secretName, cmName, secretHash, cmHash string) error {
	akvsCopy := akvs.DeepCopy()
	if secretName != "" {
		akvsCopy.Status.SecretName = secretName
		akvsCopy.Status.SecretHash = secretHash
	}
	if cmName != "" {
		akvsCopy.Status.ConfigMapName = cmName
		akvsCopy.Status.ConfigMapHash = cmHash
	}
	akvsCopy.Status.LastAzureUpdate = c.clock.Now()

	_, err := c.akvsClient.AzureKeyVaultV2beta1().AzureKeyVaultSecrets(akvs.Namespace).UpdateStatus(context.TODO(), akvsCopy, metav1.UpdateOptions{})
	return err
}

func (c *Controller) updateAzureKeyVaultSecretStatusForSecret(akvs *akv.AzureKeyVaultSecret, secretHash string) error {
	secretName := determineSecretName(akvs)
	now := c.clock.Now()

	akvsCopy := akvs.DeepCopy()
	akvsCopy.Status.SecretName = secretName
	akvsCopy.Status.SecretHash = secretHash
	akvsCopy.Status.LastAzureUpdate = now

	_, err := c.akvsClient.AzureKeyVaultV2beta1().AzureKeyVaultSecrets(akvs.Namespace).UpdateStatus(context.TODO(), akvsCopy, metav1.UpdateOptions{})
	return err
}

func (c *Controller) updateAzureKeyVaultSecretStatusForConfigMap(akvs *akv.AzureKeyVaultSecret, cmHash string) error {
	cmName := determineConfigMapName(akvs)

	akvsCopy := akvs.DeepCopy()
	akvsCopy.Status.ConfigMapName = cmName
	akvsCopy.Status.ConfigMapHash = cmHash
	akvsCopy.Status.LastAzureUpdate = c.clock.Now()

	_, err := c.akvsClient.AzureKeyVaultV2beta1().AzureKeyVaultSecrets(akvs.Namespace).UpdateStatus(context.TODO(), akvsCopy, metav1.UpdateOptions{})
	return err
}

func handleKeyVaultError(err error, key string) bool {
	exit := false
	if err != nil {
		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			klog.InfoS("azurekeyvaultsecret in work queue no longer exists", "key", key)
			exit = true
		}
	}
	return exit
}
