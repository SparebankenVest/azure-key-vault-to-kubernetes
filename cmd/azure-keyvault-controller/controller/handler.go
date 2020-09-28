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
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2alpha1"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	listers "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/listers/azurekeyvault/v2alpha1"
)

// Handler process work on workqueues
type Handler struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// azureKeyvaultClientset is a clientset for our own API group
	azureKeyvaultClientset clientset.Interface

	secretsLister              corelisters.SecretLister
	azureKeyVaultSecretsLister listers.AzureKeyVaultSecretLister

	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder

	vaultService vault.Service
	clock        Timer
}

// AzurePollFrequency controls time durations to wait between polls to Azure Key Vault for changes
type AzurePollFrequency struct {
	// Normal is the time duration to wait between polls to Azure Key Vault for changes
	Normal time.Duration

	// MaxFailuresBeforeSlowingDown controls how many failures are accepted before reducing the frequency to Slow
	MaxFailuresBeforeSlowingDown int

	// Slow is the time duration to wait between polls to Azure Key Vault for changes, after MaxFailuresBeforeSlowingDown is reached
	Slow time.Duration
}

//NewHandler returns a new Handler
func NewHandler(kubeclientset kubernetes.Interface, azureKeyvaultClientset clientset.Interface, secretLister corelisters.SecretLister, azureKeyVaultSecretsLister listers.AzureKeyVaultSecretLister, azureKeyVaultSecretIdentitiesLister listers.AzureKeyVaultSecretIdentityLister, recorder record.EventRecorder, vaultService vault.Service, azureFrequency AzurePollFrequency) *Handler {
	return &Handler{
		kubeclientset:              kubeclientset,
		azureKeyvaultClientset:     azureKeyvaultClientset,
		secretsLister:              secretLister,
		azureKeyVaultSecretsLister: azureKeyVaultSecretsLister,
		recorder:                   recorder,
		vaultService:               vaultService,
		clock:                      &Clock{},
	}
}

// kubernetesSyncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the AzureKeyVaultSecret resource
// with the current status of the resource.
func (h *Handler) kubernetesSyncHandler(key string) error {
	var azureKeyVaultSecret *akv.AzureKeyVaultSecret
	var secret *corev1.Secret
	var err error

	if azureKeyVaultSecret, err = h.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	if secret, err = h.getOrCreateKubernetesSecret(azureKeyVaultSecret); err != nil {
		return err
	}

	if !metav1.IsControlledBy(secret, azureKeyVaultSecret) { // checks if the object has a controllerRef set to the given owner
		msg := fmt.Sprintf(MessageResourceExists, secret.Name)
		log.Warning(msg)
		h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (h *Handler) azureSyncHandler(key string) error {
	var azureKeyVaultSecret *akv.AzureKeyVaultSecret
	var secret *corev1.Secret
	var secretValue map[string][]byte
	var err error

	log.Debugf("Checking state for %s in Azure", key)
	if azureKeyVaultSecret, err = h.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	log.Debugf("Getting secret value for %s in Azure", key)
	if secretValue, err = h.getSecretFromKeyVault(azureKeyVaultSecret); err != nil {
		msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
		log.Errorf("failed to get secret value for '%s' from Azure Key vault '%s' using object name '%s', error: %+v", key, azureKeyVaultSecret.Spec.Vault.Name, azureKeyVaultSecret.Spec.Vault.Object.Name, err)
		h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrAzureVault, msg)
		return fmt.Errorf(msg)
	}

	secretHash := getMD5Hash(secretValue)

	log.Debugf("Checking if secret value for %s has changed in Azure", key)
	if azureKeyVaultSecret.Status.SecretHash != secretHash {
		log.Infof("Secret has changed in Azure Key Vault for AzureKeyvVaultSecret %s. Updating Secret now.", azureKeyVaultSecret.Name)

		if secret, err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Update(createNewSecret(azureKeyVaultSecret, secretValue)); err != nil {
			log.Warningf("Failed to create Secret, Error: %+v", err)
			return err
		}

		log.Warningf("Secret value will now change for Secret '%s'. Any resources (like Pods) using this Secrets must be restarted to pick up the new value. Details: https://github.com/kubernetes/kubernetes/issues/22368", secret.Name)
		h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSyncedWithAzure)
	}

	log.Debugf("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
	if err = h.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secretHash); err != nil {
		return err
	}

	return nil
}

func (h *Handler) getSecretFromKeyVault(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (map[string][]byte, error) {
	var secretHandler KubernetesSecretHandler

	switch azureKeyVaultSecret.Spec.Vault.Object.Type {
	case akv.AzureKeyVaultObjectTypeSecret:
		transformator, err := transformers.CreateTransformator(&azureKeyVaultSecret.Spec.Output)
		if err != nil {
			return nil, err
		}
		secretHandler = NewAzureSecretHandler(azureKeyVaultSecret, h.vaultService, *transformator)
	case akv.AzureKeyVaultObjectTypeCertificate:
		secretHandler = NewAzureCertificateHandler(azureKeyVaultSecret, h.vaultService)
	case akv.AzureKeyVaultObjectTypeKey:
		secretHandler = NewAzureKeyHandler(azureKeyVaultSecret, h.vaultService)
	case akv.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		secretHandler = NewAzureMultiKeySecretHandler(azureKeyVaultSecret, h.vaultService)
	default:
		return nil, fmt.Errorf("azure key vault object type '%s' not currently supported", azureKeyVaultSecret.Spec.Vault.Object.Type)
	}
	return secretHandler.Handle()
}

func (h *Handler) getAzureKeyVaultSecret(key string) (*akv.AzureKeyVaultSecret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	azureKeyVaultSecret, err := h.azureKeyVaultSecretsLister.AzureKeyVaultSecrets(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return azureKeyVaultSecret, err
}

func (h *Handler) getOrCreateKubernetesSecret(azureKeyVaultSecret *akv.AzureKeyVaultSecret) (*corev1.Secret, error) {
	var secret *corev1.Secret
	var secretValues map[string][]byte
	var err error

	secretName := azureKeyVaultSecret.Spec.Output.Secret.Name
	if secretName == "" {
		return nil, fmt.Errorf("output secret name must be specified using spec.output.secret.name")
	}

	if secret, err = h.secretsLister.Secrets(azureKeyVaultSecret.Namespace).Get(secretName); err != nil {
		if errors.IsNotFound(err) {
			secretValues, err = h.getSecretFromKeyVault(azureKeyVaultSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret from Azure Key Vault for secret '%s'/'%s', error: %+v", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, err)
			}

			if secret, err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(createNewSecret(azureKeyVaultSecret, secretValues)); err != nil {
				return nil, err
			}

			log.Infof("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
			if err = h.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, getMD5Hash(secretValues)); err != nil {
				return nil, err
			}

			return secret, nil
		}
	}

	if secretName != secret.Name {
		// Name of secret has changed in AzureKeyVaultSecret, so we need to delete current Secret and recreate
		// under new name

		// Delete secret
		if err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Delete(secret.Name, nil); err != nil {
			return nil, err
		}

		// Recreate secret under new Name
		if secret, err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(createNewSecret(azureKeyVaultSecret, secretValues)); err != nil {
			return nil, err
		}
		return secret, nil
	}

	if hasAzureKeyVaultSecretChanged(azureKeyVaultSecret, secret) {
		log.Infof("AzureKeyVaultSecret %s/%s output.secret values has changed and requires update to Secret %s", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, secretName)
		secret, err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Update(createNewSecret(azureKeyVaultSecret, secret.Data))
	}

	return secret, err
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

func (h *Handler) updateAzureKeyVaultSecretStatus(azureKeyVaultSecret *akv.AzureKeyVaultSecret, secretHash string) error {
	secretName := determineSecretName(azureKeyVaultSecret)

	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance

	azureKeyVaultSecretCopy := azureKeyVaultSecret.DeepCopy()
	azureKeyVaultSecretCopy.Status.SecretHash = secretHash
	azureKeyVaultSecretCopy.Status.LastAzureUpdate = h.clock.Now()
	azureKeyVaultSecretCopy.Status.SecretName = secretName

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the AzureKeyVaultSecret resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := h.azureKeyvaultClientset.AzurekeyvaultV2alpha1().AzureKeyVaultSecrets(azureKeyVaultSecret.Namespace).UpdateStatus(azureKeyVaultSecretCopy)
	return err
}

func handleKeyVaultError(err error, key string) bool {
	log.Debugf("Handling error for '%s' in AzureKeyVaultSecret: %s", key, err.Error())
	if err != nil {
		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			log.Debugf("Error for '%s' was 'Not Found'", key)

			utilruntime.HandleError(fmt.Errorf("AzureKeyVaultSecret '%s' in work queue no longer exists", key))
			return true
		}
	}
	return false
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the AzureKeyVaultSecret resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that AzureKeyVaultSecret resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (h *Handler) handleObject(obj interface{}) (*akv.AzureKeyVaultSecret, bool, error) {
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

		azureKeyVaultSecret, err := h.azureKeyVaultSecretsLister.AzureKeyVaultSecrets(object.GetNamespace()).Get(ownerRef.Name)
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
