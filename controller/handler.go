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
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/SparebankenVest/azure-keyvault-controller/controller/vault"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	clientset "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/clientset/versioned"
	listers "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/listers/azurekeyvaultcontroller/v1alpha1"
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

	keyVaultService *vault.AzureKeyVaultService
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
func NewHandler(kubeclientset kubernetes.Interface, azureKeyvaultClientset clientset.Interface, secretLister corelisters.SecretLister, azureKeyVaultSecretsLister listers.AzureKeyVaultSecretLister, azureFrequency AzurePollFrequency) *Handler {
	log.Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Tracef)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	return &Handler{
		kubeclientset:              kubeclientset,
		azureKeyvaultClientset:     azureKeyvaultClientset,
		secretsLister:              secretLister,
		azureKeyVaultSecretsLister: azureKeyVaultSecretsLister,
		recorder:                   recorder,
		keyVaultService:            vault.NewAzureKeyVaultService(),
	}
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the AzureKeyVaultSecret resource
// with the current status of the resource.
func (h *Handler) syncHandler(key string) error {
	var azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret
	var secret *corev1.Secret
	var err error

	// log.Infof("Checking state for %s", key)

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

	// log.Info(MessageResourceSynced)
	h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (h *Handler) azureSyncHandler(key string) error {
	var azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret
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
	if secretValue, err = h.keyVaultService.GetObject(azureKeyVaultSecret); err != nil {
		msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
		log.Errorf("failed to get secret value for '%s' from Azure Key vault '%s' using object name '%s', error: %+v", key, azureKeyVaultSecret.Spec.Vault.Name, azureKeyVaultSecret.Spec.Vault.Object.Name, err)
		h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrAzureVault, msg)
		return fmt.Errorf(msg)
	}

	secretHash := getMD5Hash(secretValue)

	log.Debugf("Checking if secret value for %s has changed in Azure", key)
	if azureKeyVaultSecret.Status.SecretHash != secretHash {
		log.Infof("Secret has changed in Azure Key Vault for AzureKeyvVaultSecret %s. Updating Secret now.", azureKeyVaultSecret.Name)

		newSecret, err := h.createNewSecret(azureKeyVaultSecret, secretValue)
		if err != nil {
			msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
			log.Error(msg)
			return fmt.Errorf(msg)
		}

		if secret, err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Update(newSecret); err != nil {
			log.Warningf("Failed to create Secret, Error: %+v", err)
			return err
		}

		log.Debugf("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
		if err = h.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secret); err != nil {
			return err
		}

		log.Warningf("Secret value will now change for Secret '%s'. Any resources (like Pods) using this Secrets must be restarted to pick up the new value. Details: https://github.com/kubernetes/kubernetes/issues/22368", azureKeyVaultSecret.Name)
		h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSyncedWithAzure)
	}

	return nil
}

func (h *Handler) getAzureKeyVaultSecret(key string) (*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, error) {
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

func (h *Handler) getOrCreateKubernetesSecret(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (*corev1.Secret, error) {
	var secret *corev1.Secret
	var secretValues map[string][]byte
	var err error

	secretName := azureKeyVaultSecret.Spec.Output.Secret.Name
	if secretName == "" {
		secretName = azureKeyVaultSecret.Name
	}

	if secretName == "" {
		return nil, fmt.Errorf("%s: secret name must be specified", azureKeyVaultSecret.Name)
	}

	if secret, err = h.secretsLister.Secrets(azureKeyVaultSecret.Namespace).Get(secretName); err != nil {
		if errors.IsNotFound(err) {
			var newSecret *corev1.Secret

			secretValues, err = h.keyVaultService.GetObject(azureKeyVaultSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret from Azure Key Vault for secret '%s'/'%s', error: %+v", azureKeyVaultSecret.Namespace, azureKeyVaultSecret.Name, err)
			}

			if newSecret, err = h.createNewSecret(azureKeyVaultSecret, secretValues); err != nil {
				msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
				h.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrAzureVault, msg)
				return nil, fmt.Errorf(msg)
			}

			if secret, err = h.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(newSecret); err != nil {
				return nil, err
			}

			log.Infof("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
			if err = h.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secret); err != nil {
				return nil, err
			}

			return secret, nil
		}
	}

	return secret, err
}

func (h *Handler) updateAzureKeyVaultSecretStatus(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, secret *corev1.Secret) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	azureKeyVaultSecretCopy := azureKeyVaultSecret.DeepCopy()
	secretHash := getMD5Hash(secret.Data)
	azureKeyVaultSecretCopy.Status.SecretHash = secretHash
	azureKeyVaultSecretCopy.Status.LastAzureUpdate = metav1.Time{Time: time.Now()}

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the AzureKeyVaultSecret resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := h.azureKeyvaultClientset.AzurekeyvaultcontrollerV1alpha1().AzureKeyVaultSecrets(azureKeyVaultSecret.Namespace).UpdateStatus(azureKeyVaultSecretCopy)
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
func (h *Handler) handleObject(obj interface{}) (*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, bool, error) {
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
func (h *Handler) createNewSecret(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, azureSecretValue map[string][]byte) (*corev1.Secret, error) {
	secretName := determineSecretName(azureKeyVaultSecret)
	secretType := determineSecretType(azureKeyVaultSecret, azureSecretValue)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: azureKeyVaultSecret.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(azureKeyVaultSecret, schema.GroupVersionKind{
					Group:   azureKeyVaultSecretv1alpha1.SchemeGroupVersion.Group,
					Version: azureKeyVaultSecretv1alpha1.SchemeGroupVersion.Version,
					Kind:    "AzureKeyVaultSecret",
				}),
			},
		},
		Type: secretType,
		Data: azureSecretValue,
	}, nil
}

func determineSecretName(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) string {
	name := azureKeyVaultSecret.Spec.Output.Secret.Name
	if name == "" {
		name = azureKeyVaultSecret.Name
	}
	return name
}

func determineSecretType(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, azureSecretValue map[string][]byte) corev1.SecretType {
	if azureKeyVaultSecret.Spec.Vault.Object.Type == azureKeyVaultSecretv1alpha1.AzureKeyVaultObjectTypeCertificate && len(azureSecretValue) == 2 {
		return corev1.SecretTypeTLS
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
