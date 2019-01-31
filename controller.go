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

package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	clientset "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/clientset/versioned"
	keyvaultScheme "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/clientset/versioned/scheme"
	informers "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/informers/externalversions/azurekeyvaultcontroller/v1alpha1"
	listers "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/listers/azurekeyvaultcontroller/v1alpha1"
	"github.com/SparebankenVest/azure-keyvault-controller/vault"
)

const controllerAgentName = "azure-keyvault-controller"

const (
	// SuccessSynced is used as part of the Event 'reason' when a AzureKeyVaultSecret is synced
	SuccessSynced = "Synced"

	// ErrResourceExists is used as part of the Event 'reason' when a AzureKeyVaultSecret fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// ErrAzureVault is used as part of the Event 'reason' when a AzureKeyVaultSecret fails
	// to sync due to a Secret of the same name already existing.
	ErrAzureVault = "ErrAzureVault"

	// FailedAzureKeyVault is the message used for Events when a resource
	// fails to get secret from Azure Key Vault
	FailedAzureKeyVault = "Failed to get secret for '%s' from Azure Key Vault '%s'"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Deployment already existing
	MessageResourceExists = "Resource '%s' already exists and is not managed by AzureKeyVaultSecret"

	// MessageResourceSynced is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully
	MessageResourceSynced = "AzureKeyVaultSecret synced successfully"

	// MessageResourceSyncedWithAzure is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully after getting updated secret from Azure Key Vault
	MessageResourceSyncedWithAzure = "AzureKeyVaultSecret synced successfully with Azure Key Vault"
)

// Controller is the controller implementation for AzureKeyVaultSecret resources
type Controller struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// azureKeyvaultClientset is a clientset for our own API group
	azureKeyvaultClientset clientset.Interface

	secretsLister              corelisters.SecretLister
	secretsSynced              cache.InformerSynced
	azureKeyVaultSecretsLister listers.AzureKeyVaultSecretLister
	azureKeyVaultSecretsSynced cache.InformerSynced

	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	workqueue      workqueue.RateLimitingInterface
	workqueueAzure workqueue.RateLimitingInterface
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}

// NewController returns a new AzureKeyVaultSecret controller
func NewController(kubeclientset kubernetes.Interface, azureKeyvaultClientset clientset.Interface, secretInformer coreinformers.SecretInformer, azureKeyVaultSecretsInformer informers.AzureKeyVaultSecretInformer) *Controller {
	// Create event broadcaster
	// Add azure-keyvault-controller types to the default Kubernetes Scheme so Events can be
	// logged for azure-keyvault-controller types.
	utilruntime.Must(keyvaultScheme.AddToScheme(scheme.Scheme))
	log.Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Tracef)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:              kubeclientset,
		azureKeyvaultClientset:     azureKeyvaultClientset,
		secretsLister:              secretInformer.Lister(),
		secretsSynced:              secretInformer.Informer().HasSynced,
		azureKeyVaultSecretsLister: azureKeyVaultSecretsInformer.Lister(),
		azureKeyVaultSecretsSynced: azureKeyVaultSecretsInformer.Informer().HasSynced,
		workqueue:                  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "AzureKeyVaultSecrets"),
		workqueueAzure:             workqueue.NewNamedRateLimitingQueue(workqueue.NewItemFastSlowRateLimiter(azureVaultFastRate, azureVaultSlowRate, azureVaultMaxFastAttempts), "AzureKeyVault"),
		recorder:                   recorder,
	}

	log.Info("Setting up event handlers")
	// Set up an event handler for when AzureKeyVaultSecret resources change
	azureKeyVaultSecretsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret := obj.(*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret)
			log.Debugf("AzureKeyVaultSecret '%s' added. Adding to queue.", secret.Name)
			controller.enqueueAzureKeyVaultSecret(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			newSecret := new.(*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret)
			oldSecret := old.(*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret)

			if newSecret.ResourceVersion == oldSecret.ResourceVersion {
				log.Debugf("AzureKeyVaultSecret '%s' added to Azure queue to check if changed in Azure.", newSecret.Name)
				// Check if secret has changed in Azure
				controller.enqueueAzurePoll(new)
				return
			}

			log.Debugf("AzureKeyVaultSecret '%s' changed. Adding to queue.", newSecret.Name)
			controller.enqueueAzureKeyVaultSecret(new)
		},
		DeleteFunc: func(obj interface{}) {
			secret := obj.(*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret)
			log.Debugf("AzureKeyVaultSecret '%s' deleted. Adding to delete queue.", secret.Name)
			controller.enqueueDeleteAzureKeyVaultSecret(obj)
		},
	})

	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a AzureKeyVaultSecret resource will enqueue that Secret resource for
	// processing. This way, we don't need to implement custom logic for
	// handling AzureKeyVaultSecret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret := obj.(*corev1.Secret)
			log.Debugf("Secret '%s' added. Handling.", secret.Name)
			controller.handleObject(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			newSecret := new.(*corev1.Secret)
			oldSecret := old.(*corev1.Secret)

			if newSecret.ResourceVersion == oldSecret.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different RVs.
				return
			}
			secret := new.(*corev1.Secret)
			log.Debugf("Secret '%s' controlled by AzureKeyVaultSecret changed. Handling.", secret.Name)
			controller.handleObject(new)
		},
		DeleteFunc: func(obj interface{}) {
			secret := obj.(*corev1.Secret)
			log.Debugf("Secret '%s' deleted. Handling.", secret.Name)
			controller.handleObject(obj)
		},
	})

	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()
	defer c.workqueueAzure.ShutDown()

	// Start the informer factories to begin populating the informer caches
	log.Info("Starting AzureKeyVaultSecret controller")

	// Wait for the caches to be synced before starting workers
	log.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.secretsSynced, c.azureKeyVaultSecretsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	log.Info("Starting workers")
	// Launch two workers to process AzureKeyVaultSecret resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
		go wait.Until(c.runAzureWorker, time.Second, stopCh)
	}

	log.Info("Started workers")
	<-stopCh
	log.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker() {
	for c.processNextWorkItem(c.workqueue, false) {
	}
}

func (c *Controller) runAzureWorker() {
	for c.processNextWorkItem(c.workqueueAzure, true) {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem(queue workqueue.RateLimitingInterface, syncAzure bool) bool {
	log.Debug("Processing next work item in queue...")
	obj, shutdown := queue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		defer queue.Done(obj)
		var key string
		var ok bool

		if key, ok = obj.(string); !ok {
			queue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		var err error
		if syncAzure {
			log.Debugf("Handling '%s' in Azure queue...", key)
			err = c.azureSyncHandler(key)
		} else {
			log.Debugf("Handling '%s' in default queue...", key)
			err = c.syncHandler(key)
		}

		if err != nil {
			queue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}

		queue.Forget(obj)
		log.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		log.Error(err)
		return true
	}

	return true
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

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the AzureKeyVaultSecret resource
// with the current status of the resource.
func (c *Controller) syncHandler(key string) error {
	var azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret
	var secret *corev1.Secret
	var err error

	// log.Infof("Checking state for %s", key)

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

	// log.Infof("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
	// if err = c.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secret); err != nil {
	// 	return err
	// }

	// log.Info(MessageResourceSynced)
	c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *Controller) azureSyncHandler(key string) error {
	var azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret
	var secret *corev1.Secret
	var secretValue string
	var err error

	log.Debugf("Checking state for %s in Azure", key)
	if azureKeyVaultSecret, err = c.getAzureKeyVaultSecret(key); err != nil {
		if exit := handleKeyVaultError(err, key); exit {
			return nil
		}
		return err
	}

	log.Debugf("Getting secret value for %s in Azure", key)
	if secretValue, err = vault.GetSecret(azureKeyVaultSecret); err != nil {
		msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
		log.Warning(msg)
		c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrAzureVault, msg)
		return fmt.Errorf(msg)
	}

	secretHash := getMD5Hash(secretValue)

	log.Debugf("Checking if secret value for %s has changed in Azure", key)
	if azureKeyVaultSecret.Status.SecretHash != secretHash {
		log.Infof("Secret has changed in Azure Key Vault for AzureKeyvVaultSecret %s. Updating Secret now.", azureKeyVaultSecret.Name)
		log.Debugf("Old secret hash: %s", azureKeyVaultSecret.Status.SecretHash)
		log.Debugf("New secret hash: %s", secretHash)
		log.Debugf("New secret value: %s", secretValue)
		newSecret, err := createNewSecret(azureKeyVaultSecret, &secretValue)
		if err != nil {
			msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
			log.Error(msg)
			return fmt.Errorf(msg)
		}

		if secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Update(newSecret); err != nil {
			log.Warningf("Failed to create Secret, Error: %+v", err)
			return err
		}

		log.Debugf("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
		if err = c.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secret); err != nil {
			return err
		}

		c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSyncedWithAzure)
	}

	return nil
}

func (c *Controller) getAzureKeyVaultSecret(key string) (*azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	azureKeyVaultSecret, err := c.azureKeyVaultSecretsLister.AzureKeyVaultSecrets(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return azureKeyVaultSecret, err
}

func (c *Controller) getOrCreateKubernetesSecret(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (*corev1.Secret, error) {
	var secret *corev1.Secret
	var err error

	secretName := azureKeyVaultSecret.Spec.OutputSecret.Name
	if secretName == "" {
		return nil, fmt.Errorf("%s: secret name must be specified", azureKeyVaultSecret.Name)
	}

	if secret, err = c.secretsLister.Secrets(azureKeyVaultSecret.Namespace).Get(secretName); err != nil {
		if errors.IsNotFound(err) {
			var newSecret *corev1.Secret

			if newSecret, err = createNewSecret(azureKeyVaultSecret, nil); err != nil {
				msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
				c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrAzureVault, msg)
				return nil, fmt.Errorf(msg)
			}

			if secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(newSecret); err != nil {
				return nil, err
			}

			log.Infof("Updating status for AzureKeyVaultSecret '%s'", azureKeyVaultSecret.Name)
			if err = c.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secret); err != nil {
				return nil, err
			}

			return secret, nil
		}
	}

	return secret, err
}

func (c *Controller) updateAzureKeyVaultSecretStatus(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, secret *corev1.Secret) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	azureKeyVaultSecretCopy := azureKeyVaultSecret.DeepCopy()
	secretValue := string(secret.Data[azureKeyVaultSecret.Spec.OutputSecret.KeyName])
	secretHash := getMD5Hash(secretValue)
	azureKeyVaultSecretCopy.Status.SecretHash = secretHash
	azureKeyVaultSecretCopy.Status.LastAzureUpdate = time.Now()

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the AzureKeyVaultSecret resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.azureKeyvaultClientset.AzurekeyvaultcontrollerV1alpha1().AzureKeyVaultSecrets(azureKeyVaultSecret.Namespace).UpdateStatus(azureKeyVaultSecretCopy)
	return err
}

// enqueueAzureKeyVaultSecret takes a AzureKeyVaultSecret resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than AzureKeyVaultSecret.
func (c *Controller) enqueueAzureKeyVaultSecret(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
}

// enqueueAzureKeyVaultSecret takes a AzureKeyVaultSecret resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than AzureKeyVaultSecret.
func (c *Controller) enqueueAzurePoll(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueueAzure.AddRateLimited(key)
}

// dequeueAzureKeyVaultSecret takes a AzureKeyVaultSecret resource and converts it into a namespace/name
// string which is then put onto the work queue for deltion. This method should *not* be
// passed resources of any type other than AzureKeyVaultSecret.
func (c *Controller) enqueueDeleteAzureKeyVaultSecret(obj interface{}) {
	var key string
	var err error

	if key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)

	// Getting default key to remove from Azure work queue
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueueAzure.Forget(key)
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the AzureKeyVaultSecret resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that AzureKeyVaultSecret resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		log.Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}

	log.Debugf("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a AzureKeyVaultSecret, we should not do anything more
		// with it.
		if ownerRef.Kind != "AzureKeyVaultSecret" {
			return
		}

		azureKeyVaultSecret, err := c.azureKeyVaultSecretsLister.AzureKeyVaultSecrets(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			log.Infof("ignoring orphaned object '%s' of azureKeyVaultSecret '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		c.enqueueAzureKeyVaultSecret(azureKeyVaultSecret)
		return
	}
}

// newSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func createNewSecret(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, azureSecretValue *string) (*corev1.Secret, error) {
	var secretValue string

	if azureSecretValue == nil {
		var err error
		secretValue, err = vault.GetSecret(azureKeyVaultSecret)
		if err != nil {
			msg := fmt.Sprintf(FailedAzureKeyVault, azureKeyVaultSecret.Name, azureKeyVaultSecret.Spec.Vault.Name)
			return nil, fmt.Errorf(msg)
		}
	} else {
		secretValue = *azureSecretValue
	}

	stringData := make(map[string]string)
	stringData[azureKeyVaultSecret.Spec.OutputSecret.KeyName] = secretValue

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      azureKeyVaultSecret.Spec.OutputSecret.Name,
			Namespace: azureKeyVaultSecret.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(azureKeyVaultSecret, schema.GroupVersionKind{
					Group:   azureKeyVaultSecretv1alpha1.SchemeGroupVersion.Group,
					Version: azureKeyVaultSecretv1alpha1.SchemeGroupVersion.Version,
					Kind:    "AzureKeyVaultSecret",
				}),
			},
		},
		Type:       azureKeyVaultSecret.Spec.OutputSecret.Type,
		StringData: stringData,
	}, nil
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
