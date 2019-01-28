package main

import (
	"context"
	"fmt"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	clientset "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/clientset/versioned"
	informers "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/informers/externalversions/azurekeyvaultcontroller/v1alpha1"
	listers "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/listers/azurekeyvaultcontroller/v1alpha1"
)

const controllerAgentName = "azure-keyvault-controller"

const (
	// SuccessSynced is used as part of the Event 'reason' when a AzureKeyVaultSecret is synced
	SuccessSynced = "Synced"
	// ErrResourceExists is used as part of the Event 'reason' when a AzureKeyVaultSecret fails
	// to sync due to a Deployment of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Deployment already existing
	MessageResourceExists = "Resource %q already exists and is not managed by AzureKeyVaultSecret"
	// MessageResourceSynced is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully
	MessageResourceSynced = "AzureKeyVaultSecret synced successfully"
)

// Controller is the controller implementation for AzureKeyVaultSecret resources
type Controller struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// sampleclientset is a clientset for our own API group
	sampleclientset clientset.Interface

	secretsLister              corelisters.SecretLister
	secretsSynced              cache.InformerSynced
	azureKeyVaultSecretsLister listers.AzureKeyVaultSecretLister
	azureKeyVaultSecretsSynced cache.InformerSynced

	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	workqueue workqueue.RateLimitingInterface
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	// recorder record.EventRecorder
}

// NewController returns a new AzureKeyVaultSecret controller
func NewController(
	kubeclientset kubernetes.Interface,
	sampleclientset clientset.Interface,
	secretInformer coreinformers.SecretInformer,
	azureKeyVaultSecretsInformer informers.AzureKeyVaultSecretInformer) *Controller {

	// // Create event broadcaster
	// // Add sample-controller types to the default Kubernetes Scheme so Events can be
	// // logged for sample-controller types.
	// utilruntime.Must(samplescheme.AddToScheme(scheme.Scheme))
	// klog.V(4).Info("Creating event broadcaster")
	// eventBroadcaster := record.NewBroadcaster()
	// eventBroadcaster.StartLogging(klog.Infof)
	// eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	// recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:              kubeclientset,
		sampleclientset:            sampleclientset,
		secretsLister:              secretInformer.Lister(),
		secretsSynced:              secretInformer.Informer().HasSynced,
		azureKeyVaultSecretsLister: azureKeyVaultSecretsInformer.Lister(),
		azureKeyVaultSecretsSynced: azureKeyVaultSecretsInformer.Informer().HasSynced,
		workqueue:                  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "AzureKeyVaultSecrets"),
		// recorder:                   recorder,
	}

	log.Printf("Setting up event handlers")
	// Set up an event handler for when AzureKeyVaultSecret resources change
	azureKeyVaultSecretsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueAzureKeyVaultSecret,
		UpdateFunc: func(old, new interface{}) {
			// controller.enqueueAzureKeyVaultSecret(new)
			newSecret := new.(*azureKeyVaultSecretv1alpha1.Secret)
			oldSecret := old.(*azureKeyVaultSecretv1alpha1.Secret)
			if newSecret.ResourceVersion == oldSecret.ResourceVersion {
				// Periodic resync will send update events for all known Deployments.
				// Two different versions of the same Deployment will always have different RVs.
				return
			}
			controller.handleObject(new)
		},
		DeleteFunc: controller.dequeueAzureKeyVaultSecret,
	})

	// Set up an event handler for when AzureKeyVaultSecret resources change. This
	// handler will lookup the owner of the given AzureKeyVaultSecret, and if it is
	// owned by a AzureKeyVaultSecret resource will enqueue that AzureKeyVaultSecret resource for
	// processing. This way, we don't need to implement custom logic for
	// handling AzureKeyVaultSecret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleObject,
		UpdateFunc: func(old, new interface{}) {
			newSecret := new.(*corev1.Secret)
			oldSecret := old.(*corev1.Secret)
			if newSecret.ResourceVersion == oldSecret.ResourceVersion {
				// Periodic resync will send update events for all known Deployments.
				// Two different versions of the same Deployment will always have different RVs.
				return
			}
			controller.handleObject(new)
		},
		DeleteFunc: controller.handleObject,
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

	// Start the informer factories to begin populating the informer caches
	log.Printf("Starting AzureKeyVaultSecret controller")

	// Wait for the caches to be synced before starting workers
	log.Printf("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.secretsSynced, c.azureKeyVaultSecretsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	log.Printf("Starting workers")
	// Launch two workers to process AzureKeyVaultSecret resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	log.Printf("Started workers")
	<-stopCh
	log.Printf("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// AzureKeyVaultSecret resource to be synced.
		if err := c.syncHandler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(obj)
		log.Printf("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the AzureKeyVaultSecret resource
// with the current status of the resource.
func (c *Controller) syncHandler(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the AzureKeyVaultSecret resource with this namespace/name
	azureKeyVaultSecret, err := c.azureKeyVaultSecretsLister.AzureKeyVaultSecrets(namespace).Get(name)
	if err != nil {
		// The AzureKeyVaultSecret resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("AzureKeyVaultSecret '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	secretName := azureKeyVaultSecret.Spec.OutputSecret.Name
	if secretName == "" {
		// We choose to absorb the error here as the worker would requeue the
		// resource otherwise. Instead, the next time the resource is updated
		// the resource will be queued again.
		utilruntime.HandleError(fmt.Errorf("%s: secret name must be specified", key))
		return nil
	}

	// Get the secret with the name specified in AzureKeyVaultSecret.spec
	secret, err := c.secretsLister.Secrets(azureKeyVaultSecret.Namespace).Get(secretName)
	// If the resource doesn't exist, we'll create it
	if errors.IsNotFound(err) {
		secret, err = c.kubeclientset.CoreV1().Secrets(azureKeyVaultSecret.Namespace).Create(newSecret(azureKeyVaultSecret))
	}

	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// If the Secret is not controlled by this AzureKeyVaultSecret resource, we should log
	// a warning to the event recorder and return
	if !metav1.IsControlledBy(secret, azureKeyVaultSecret) { // checks if the object has a controllerRef set to the given owner
		msg := fmt.Sprintf(MessageResourceExists, secret.Name)
		// c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	// // If this number of the replicas on the AzureKeyVaultSecret resource is specified, and the
	// // number does not equal the current desired replicas on the Deployment, we
	// // should update the AzureKeyVaultSecret resource.
	// if azureKeyVaultSecret.Spec.Replicas != nil && *azureKeyVaultSecret.Spec.Replicas != *deployment.Spec.Replicas {
	// 	klog.V(4).Infof("AzureKeyVaultSecret %s replicas: %d, deployment replicas: %d", name, *azureKeyVaultSecret.Spec.Replicas, *deployment.Spec.Replicas)
	// 	deployment, err = c.kubeclientset.AppsV1().Deployments(azureKeyVaultSecret.Namespace).Update(newSecret(azureKeyVaultSecret))
	// }

	// If an error occurs during Update, we'll requeue the item so we can
	// attempt processing again later. THis could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// Finally, we update the status block of the AzureKeyVaultSecret resource to reflect the
	// current state of the world
	err = c.updateAzureKeyVaultSecretStatus(azureKeyVaultSecret, secret)
	if err != nil {
		return err
	}

	// c.recorder.Event(azureKeyVaultSecret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *Controller) updateAzureKeyVaultSecretStatus(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret, secret *corev1.Secret) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	azureKeyVaultSecretCopy := azureKeyVaultSecret.DeepCopy()
	// azureKeyVaultSecretCopy.Status.AvailableReplicas = deployment.Status.AvailableReplicas

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the AzureKeyVaultSecret resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.sampleclientset.AzurekeyvaultcontrollerV1alpha1().AzureKeyVaultSecrets(azureKeyVaultSecret.Namespace).Update(azureKeyVaultSecretCopy)
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

// dequeueAzureKeyVaultSecret takes a AzureKeyVaultSecret resource and converts it into a namespace/name
// string which is then put onto the work queue for deltion. This method should *not* be
// passed resources of any type other than AzureKeyVaultSecret.
func (c *Controller) dequeueAzureKeyVaultSecret(obj interface{}) {
	var key string
	var err error
	if key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
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
		log.Printf("Recovered deleted object '%s' from tombstone", object.GetName())
	}
	log.Printf("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a AzureKeyVaultSecret, we should not do anything more
		// with it.
		if ownerRef.Kind != "AzureKeyVaultSecret" {
			return
		}

		azureKeyVaultSecret, err := c.azureKeyVaultSecretsLister.AzureKeyVaultSecrets(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			log.Printf("ignoring orphaned object '%s' of azureKeyVaultSecret '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		c.enqueueAzureKeyVaultSecret(azureKeyVaultSecret)
		return
	}
}

// newSecret creates a new Secret for a AzureKeyVaultSecret resource. It also sets
// the appropriate OwnerReferences on the resource so handleObject can discover
// the AzureKeyVaultSecret resource that 'owns' it.
func newSecret(azureKeyVaultSecret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) *corev1.Secret {
	// labels := map[string]string{
	// 	"app":        "nginx",
	// 	"controller": azureKeyVaultSecret.Name,
	// }

	vaultClient := GetKeysClient("https://vault.azure.net")

	baseUrl := fmt.Sprintf("https://%s.vault.azure.net", azureKeyVaultSecret.Spec.Vault.Name)

	secretPack, err := vaultClient.GetSecret(context.Background(), baseUrl, azureKeyVaultSecret.Spec.Vault.ObjectName, "")
	if err != nil {
		log.Printf("failed to get Key Vault Secret, Error: %+v", err)
	}

	stringData := make(map[string]string)
	stringData[azureKeyVaultSecret.Spec.OutputSecret.KeyName] = *secretPack.Value

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
		Type:       corev1.SecretTypeOpaque,
		StringData: stringData,
	}
}
