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
	"fmt"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2alpha1"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2alpha1"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"kmodules.xyz/client-go/tools/queue"
)

func (c *Controller) initAzureKeyVaultSecret() {
	c.akvsInformerFactory.Azurekeyvault().V2alpha1().AzureKeyVaultSecrets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret, err := convertToAzureKeyVaultSecret(obj)
			if err != nil {
				log.Errorf("failed to convert to azurekeyvaultsecret: %v", err)
			}

			if c.akvsHasSecretOutput(secret) {
				log.Debugf("AzureKeyVaultSecret %s/%s added. Adding to queue.", secret.Namespace, secret.Name)
				queue.Enqueue(c.akvsCrdQueue.GetQueue(), obj)
				// queue.Enqueue(c.azureKeyVaultQueue.GetQueue(), obj)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			newSecret, err := convertToAzureKeyVaultSecret(new)
			if err != nil {
				log.Errorf("failed to convert to azurekeyvaultsecret: %v", err)
			}

			oldSecret, err := convertToAzureKeyVaultSecret(old)
			if err != nil {
				log.Errorf("failed to convert to azurekeyvaultsecret: %v", err)
			}

			// If akvs has not changed and has secret output, add to akv queue to check if secret has changed in akv
			if newSecret.ResourceVersion == oldSecret.ResourceVersion && c.akvsHasSecretOutput(newSecret) {
				log.Debugf("AzureKeyVaultSecret %s/%s not changed. Adding to Azure Key Vault queue to check if secret has changed in Azure Key Vault.", newSecret.Namespace, newSecret.Name)
				queue.Enqueue(c.azureKeyVaultQueue.GetQueue(), new)
				return
			}

			if c.akvsHasSecretOutput(newSecret) || c.akvsHasSecretOutput(oldSecret) {
				log.Debugf("AzureKeyVaultSecret %s/%s changed. Adding to queue.", newSecret.Namespace, newSecret.Name)
				queue.Enqueue(c.akvsCrdQueue.GetQueue(), new)
			}
		},
		DeleteFunc: func(obj interface{}) {
			secret, err := convertToAzureKeyVaultSecret(obj)
			if err != nil {
				log.Errorf("failed to convert to azurekeyvaultsecret: %v", err)
			}

			if c.akvsHasSecretOutput(secret) {
				log.Debugf("AzureKeyVaultSecret %s/%s deleted. Adding to delete queue.", secret.Namespace, secret.Name)
				queue.Enqueue(c.akvsCrdQueue.GetQueue(), obj)

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
}

func convertToAzureKeyVaultSecret(obj interface{}) (*v2alpha1.AzureKeyVaultSecret, error) {
	secret, ok := obj.(*v2alpha1.AzureKeyVaultSecret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		secret, ok = tombstone.Obj.(*v2alpha1.AzureKeyVaultSecret)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a AzureKeyVaultSecret %#v", obj)
		}
	}
	return secret, nil
}

func (c *Controller) syncAzureKeyVaultSecret(key string) error {
	var azureKeyVaultSecret *akv.AzureKeyVaultSecret
	var secret *corev1.Secret
	var err error

	log.Debugf("Processing AzureKeyVaultSecret %s", key)
	if azureKeyVaultSecret, err = c.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	if secret, err = c.getOrCreateKubernetesSecret(azureKeyVaultSecret); err != nil {
		return err
	}

	if !metav1.IsControlledBy(secret, azureKeyVaultSecret) { // checks if the object has a controllerRef set to the given owner
		msg := fmt.Sprintf(MessageResourceExists, secret.Name)
		log.Warning(msg)
		c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	log.Debugf("Successfully synced AzureKeyVaultSecret %s with Kubernetes Secret %s", key, fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSynced)
	return nil
}

func (c *Controller) akvsHasSecretOutput(secret *v2alpha1.AzureKeyVaultSecret) bool {
	return secret.Spec.Output.Secret.Name != ""
}

func (c *Controller) syncAzureKeyVault(key string) error {
	var azureKeyVaultSecret *akv.AzureKeyVaultSecret
	var secret *corev1.Secret
	var secretValue map[string][]byte
	var err error

	log.Debugf("Checking state for %s in Azure", key)
	if azureKeyVaultSecret, err = c.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	log.Debugf("Getting secret value for %s in Azure", key)
	if secretValue, err = c.getSecretFromKeyVault(azureKeyVaultSecret); err != nil {
		msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
		log.Errorf("failed to get secret value for '%s' from Azure Key vault '%s' using object name '%s', error: %+v", key, azureKeyVaultSecret.Spec.Vault.Name, azureKeyVaultSecret.Spec.Vault.Object.Name, err)
		c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrAzureVault, msg)
		return fmt.Errorf(msg)
	}

	secretHash := getMD5Hash(secretValue)

	log.Debugf("Checking if secret value for %s has changed in Azure", key)
	if azureKeyVaultSecret.Status.SecretHash != secretHash {
		log.Infof("Secret has changed in Azure Key Vault for AzureKeyvVaultSecret %s. Updating Secret now.", azureKeyVaultSecret.Name)

		if secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Update(createNewSecret(azureKeyVaultSecret, secretValue)); err != nil {
			log.Warningf("Failed to create Secret, Error: %+v", err)
			return err
		}

		log.Warningf("Secret value will now change for Secret '%s'. Any resources (like Pods) using this Secret must be restarted to pick up the new value. Details: https://github.com/kubernetes/kubernetes/issues/22368", secret.Name)
	}

	log.Debugf("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
	if err = c.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secretHash); err != nil {
		return err
	}

	log.Debugf("Successfully synced AzureKeyVaultSecret %s with Azure Key Vault", key)
	c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageAzureKeyVaultSecretSyncedWithAzureKeyVault)
	return nil
}

func (c *Controller) getAzureKeyVaultSecretFromSecret(secret *corev1.Secret, owner *metav1.OwnerReference) (*akv.AzureKeyVaultSecret, error) {
	return c.azureKeyVaultSecretLister.AzureKeyVaultSecrets(secret.Namespace).Get(owner.Name)
}

func (c *Controller) getSecretFromKeyVault(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (map[string][]byte, error) {
	var secretHandler KubernetesSecretHandler

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
	return secretHandler.Handle()
}

func (c *Controller) getAzureKeyVaultSecret(key string) (*akv.AzureKeyVaultSecret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	log.Debugf("Getting AzureKeyVaultSecret %s from namespace %s", name, namespace)
	azureKeyVaultSecret, err := c.azureKeyVaultSecretLister.AzureKeyVaultSecrets(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return azureKeyVaultSecret, err
}

func hasAzureKeyVaultSecretChanged(vaultSecret *akv.AzureKeyVaultSecret, secret *corev1.Secret) bool {
	secretType := determineSecretType(vaultSecret)
	if secretType != secret.Type {
		return true
	}

	// Check if dataKey has changed by trying to lookup key
	if vaultSecret.Spec.Output.Secret.DataKey != "" {
		if _, ok := secret.Data[vaultSecret.Spec.Output.Secret.DataKey]; !ok {
			return true
		}
	}
	return false
}

func (c *Controller) updateAzureKeyVaultSecretStatus(azureKeyVaultSecret *akv.AzureKeyVaultSecret, secretHash string) error {
	secretName := determineSecretName(azureKeyVaultSecret)

	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance

	azureKeyVaultSecretCopy := azureKeyVaultSecret.DeepCopy()
	azureKeyVaultSecretCopy.Status.SecretHash = secretHash
	azureKeyVaultSecretCopy.Status.LastAzureUpdate = c.clock.Now()
	azureKeyVaultSecretCopy.Status.SecretName = secretName

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the AzureKeyVaultSecret resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.akvsClient.AzurekeyvaultV2alpha1().AzureKeyVaultSecrets(azureKeyVaultSecret.Namespace).UpdateStatus(azureKeyVaultSecretCopy)
	return err
}

func handleKeyVaultError(err error, key string) bool {
	log.Debugf("Handling error for '%s' in AzureKeyVaultSecret: %s", key, err.Error())
	exit := false
	if err != nil {
		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			log.Debugf("Error for '%s' was 'Not Found'", key)

			log.Errorf("AzureKeyVaultSecret '%s' in work queue no longer exists", key)
			exit = true
		}
	}
	return exit
}
