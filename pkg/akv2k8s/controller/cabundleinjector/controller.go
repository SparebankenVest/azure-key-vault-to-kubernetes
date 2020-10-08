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

/*
	When the env-injector gets installed, a CA Cert and Key, together with a serving cert
	is installed as a Secert in the akv2k8s namespace. We monitor this secret for changes
	and copy the CA Cert into a ConfigMap in all namespaces labeled
	`azure-key-vault-env-injection: enabled`. We also monitor the label, and removed CA bundle if label is changed.
*/

package cabundleinjector

import (
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
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

type workQueueType string

const (
	// SuccessSynced is used as part of the Event 'reason' when a AzureKeyVaultSecret is synced
	SuccessSynced = "Synced"

	// ErrResourceExists is used as part of the Event 'reason' when a AzureKeyVaultSecret fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// ErrConfigMap is used as part of the Event 'reason' when a Secret sync fails
	ErrConfigMap = "ErrConfigMap"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Deployment already existing
	MessageResourceExists = "Resource '%s' already exists and is not managed by CA Bundle Injector"

	// MessageResourceSynced is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully
	MessageResourceSynced = "CA Bundle synced successfully"

	workQueueTypeSecret           workQueueType = "secret"
	workQueueTypeNewNamespace     workQueueType = "newNamespace"
	workQueueTypeChangedNamespace workQueueType = "changedNamespace"
)

type caBundleControllerConfig struct {
}

// Controller is the controller implementation for AzureKeyVaultSecret resources
type Controller struct {

	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	kubeclientset kubernetes.Interface
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder

	secretWorkqueue           workqueue.RateLimitingInterface
	newNamespaceWorkqueue     workqueue.RateLimitingInterface
	changedNamespaceWorkqueue workqueue.RateLimitingInterface

	secretsSynced    cache.InformerSynced
	namespacesSynced cache.InformerSynced

	secretLister    corelisters.SecretLister
	configMapLister corelisters.ConfigMapLister
	namespaceLister corelisters.NamespaceLister

	labelName                   string
	caBundleSecretName          string
	caBundleSecretNamespaceName string
	caBundleConfigMapName       string
}

// NewController returns a new AzureKeyVaultSecret controller
func NewController(kubeclientset kubernetes.Interface, recorder record.EventRecorder, secretInformer coreinformers.SecretInformer, namespaceInformer coreinformers.NamespaceInformer, configMapInformer coreinformers.ConfigMapInformer, labelName string, caBundleSecretNamespaceName string, caBundleSecretName string, caBundleConfigMapName string) *Controller {
	controller := &Controller{
		kubeclientset:               kubeclientset,
		recorder:                    recorder,
		secretsSynced:               secretInformer.Informer().HasSynced,
		namespacesSynced:            namespaceInformer.Informer().HasSynced,
		secretWorkqueue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CABundles"),
		newNamespaceWorkqueue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CAInjectedNewNamespaces"),
		changedNamespaceWorkqueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CAInjectedChangedNamespaces"),
		labelName:                   labelName,
		secretLister:                secretInformer.Lister(),
		configMapLister:             configMapInformer.Lister(),
		namespaceLister:             namespaceInformer.Lister(),
		caBundleSecretName:          caBundleSecretName,
		caBundleSecretNamespaceName: caBundleSecretNamespaceName,
		caBundleConfigMapName:       caBundleConfigMapName,
	}

	log.Info("Setting up event handlers")

	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a AzureKeyVaultSecret resource will enqueue that Secret resource for
	// processing. This way, we don't need to implement custom logic for
	// handling AzureKeyVaultSecret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { // When CA Bundle gets added to akv2k8s
			if secret, ok := obj.(*corev1.Secret); ok {
				if secret.Name != caBundleSecretName {
					return
				}
				log.Infof("Secret '%s' monitored by CA Bundle Injector added. Adding to queue.", secret.Name)
				controller.enqueueSecret(obj)
			}
		},
		UpdateFunc: func(old, new interface{}) { // When CA Bundle gets changed in akv2k8s
			if newSecret, ok := new.(*corev1.Secret); ok {
				oldSecret := old.(*corev1.Secret)

				if newSecret.Name != caBundleSecretName {
					return
				}

				if newSecret.ResourceVersion == oldSecret.ResourceVersion {
					// Periodic resync will send update events for all known Secrets.
					// Two different versions of the same Secret will always have different RVs.
					return
				}
				log.Infof("Secret '%s' monitored by CA Bundle Injector changed. Handling.", newSecret.Name)
				controller.enqueueSecret(new)
			}
		},
		DeleteFunc: func(obj interface{}) { // When CA Bundle gets deleted in akv2k8s
			if secret, ok := obj.(*corev1.Secret); ok {
				if secret.Name != caBundleSecretName {
					return
				}

				log.Infof("Secret '%s' monitored by CA Bundle Injector deleted. Handling.", secret.Name)
				controller.enqueueSecret(obj)
			}
		},
	})

	namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { // When a new namespace gets added, that we should add ConfigMap to
			if ns, ok := obj.(*corev1.Namespace); ok {
				lbl := ns.Labels[controller.labelName]
				if lbl == "" {
					return
				}

				log.Infof("Namespace '%s' labeled '%s' will be monitored by CA Bundle Injector. Adding to queue.", ns.Name, lbl)
				controller.enqueueNewNamespace(obj)
			}
		},
		UpdateFunc: func(old, new interface{}) { // When an existing namespace gets updated, that potentually have akv2k8s label on it
			if newNs, ok := new.(*corev1.Namespace); ok {
				oldNs := old.(*corev1.Namespace)

				if newNs.ResourceVersion == oldNs.ResourceVersion {
					// Periodic resync will send update events for all known Secrets.
					// Two different versions of the same Secret will always have different RVs.
					return
				}

				newLbl, newLblExist := newNs.Labels[controller.labelName]
				oldLbl, oldLblExist := oldNs.Labels[controller.labelName]

				if newLblExist == oldLblExist && newLbl == oldLbl {
					return // we only care if the namespace label has changed
				}

				ns := new.(*corev1.Namespace)
				log.Infof("labels in namespace '%s' changed, handling.", ns.Name)
				controller.enqueueChangedNamespace(new)
			}
		},
		// DeleteFunc: func(obj interface{}) {
		// 	ns := obj.(*corev1.Namespace)
		// 	log.Debugf("Namespace '%s' monitored by CA Bundle Injector deleted. Handling.", ns.Name)
		// 	controller.enqueueNamespace(obj)
		// },
	})

	// configMapInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
	// 	DeleteFunc: func(obj interface{}) {
	// 		ns := obj.(*corev1.ConfigMap)
	// 		log.Debugf("ConfigMap '%s' monitored by CA Bundle Injector deleted. Handling.", ns.Name)
	// 		controller.enqueueNamespace(obj)
	// 	},
	// })

	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.secretWorkqueue.ShutDown()
	defer c.newNamespaceWorkqueue.ShutDown()
	defer c.changedNamespaceWorkqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	log.Info("Starting CA Bundle Injector controller")

	// Wait for the caches to be synced before starting workers
	log.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.secretsSynced, c.namespacesSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	log.Info("Starting workers")
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runSecretWorker, time.Second, stopCh)
		go wait.Until(c.runNewNamespaceWorker, time.Second, stopCh)
		go wait.Until(c.runChangedNamespaceWorker, time.Second, stopCh)
	}

	log.Info("Started workers")
	<-stopCh
	log.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runSecretWorker() {
	for c.processNextWorkItem(c.secretWorkqueue, workQueueTypeSecret) {
	}
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runNewNamespaceWorker() {
	for c.processNextWorkItem(c.newNamespaceWorkqueue, workQueueTypeNewNamespace) {
	}
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runChangedNamespaceWorker() {
	for c.processNextWorkItem(c.changedNamespaceWorkqueue, workQueueTypeChangedNamespace) {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem(queue workqueue.RateLimitingInterface, typeOfQueue workQueueType) bool {
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
		var successMsg string

		if key, ok = obj.(string); !ok {
			queue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		var err error
		log.Debugf("Handling '%s' in queue...", key)

		switch typeOfQueue {
		case workQueueTypeSecret:
			successMsg = "Successfully synced CA Bundle from updated secret '%s' to all enabled namespaces"
			err = c.syncHandlerSecret(key)
		case workQueueTypeNewNamespace:
			successMsg = "Successfully synced CA Bundle to new namespace '%s'"
			err = c.syncHandlerNewNamespace(key)
		case workQueueTypeChangedNamespace:
			successMsg = "Successfully synced CA Bundle to changed namespace '%s'"
			err = c.syncHandlerChangedNamespace(key)
		}

		if err != nil {
			queue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}

		queue.Forget(obj)
		log.Infof(successMsg, key)
		return nil
	}(obj)

	if err != nil {
		log.Error(err)
		return true
	}

	return true
}

//syncHandler for secrets
func (c *Controller) syncHandlerSecret(key string) error {
	/*
		1. Get Secret
		2. Get all akv2k8s-injector enabled namespaces
		3. Create ConfigMaps containing CA cert in namespaces
	*/

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	log.Debugf("pulling secret '%s' from namespace '%s'", name, namespace)

	// Get the Secret resource with this namespace/name
	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		// The Secret resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("secret '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	labelSelector := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"azure-key-vault-env-injection": "enabled",
		},
	}

	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return err
	}

	labelledNamespaces, err := c.namespaceLister.List(selector)
	if err != nil {
		return err
	}

	log.Infof("looping all labelled namespaces looking for config map '%s' to update", c.caBundleConfigMapName)

	for _, ns := range labelledNamespaces {
		configMap, err := c.configMapLister.ConfigMaps(ns.Name).Get(c.caBundleConfigMapName)

		// If the resource doesn't exist, we'll create it
		if errors.IsNotFound(err) {
			log.Debugf("configmap '%s' not found in labelled namespace '%s' - creating configmap now", c.caBundleConfigMapName, ns.Name)
			newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			configMap, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Create(newConfigMap)
			if err != nil {
				msg := fmt.Sprintf("failed to create configmap %s in namespace %s", newConfigMap.Name, ns.Name)
				c.recorder.Event(newConfigMap, corev1.EventTypeWarning, ErrConfigMap, msg)
				log.Errorf("%s, error: %+v", msg, err)
				return err
			}
			return nil
		}

		// If an error occurs during Get/Create, we'll requeue the item so we can
		// attempt processing again later. This could have been caused by a
		// temporary network failure, or any other transient reason.
		if err != nil {
			return err
		}

		// If the ConfigMap is not controlled by this Secret resource, we should log
		// a warning to the event recorder and return error msg.
		if !metav1.IsControlledBy(configMap, secret) {
			msg := fmt.Sprintf(MessageResourceExists, configMap.Name)
			c.recorder.Event(secret, corev1.EventTypeWarning, ErrResourceExists, msg)
			return fmt.Errorf(msg)
		}

		// If CA cert in ConfigMap resource is not the same as in Secret resource, we
		// should update the ConfigMap resource.
		if configMap.Data["caCert"] != secret.StringData["caCert"] {
			log.Infof("secret %s updated: updating config map: %s", secret.Name, configMap.Name)
			newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			configMap, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Update(newConfigMap)

			if err != nil {
				msg := fmt.Sprintf("failed to update configmap %s in namespace %s", newConfigMap.Name, ns.Name)
				c.recorder.Event(newConfigMap, corev1.EventTypeWarning, ErrConfigMap, msg)
				log.Errorf("%s, error: %+v", msg, err)
				return err
			}
		}

		// If an error occurs during Update, we'll requeue the item so we can
		// attempt processing again later. This could have been caused by a
		// temporary network failure, or any other transient reason.
		if err != nil {
			return err
		}
	}

	c.recorder.Event(secret, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

//syncHandler for new labelled namespaces
func (c *Controller) syncHandlerNewNamespace(key string) error {
	ns, err := c.namespaceLister.Get(key)
	if err != nil {
		return err
	}

	log.Debugf("Looking for configmap '%s' in labelled namespace '%s'", c.caBundleConfigMapName, key)
	cm, err := c.configMapLister.ConfigMaps(key).Get(c.caBundleConfigMapName)

	if err != nil {
		if errors.IsNotFound(err) { // if configmap does not exist, create it
			log.Debugf("configmap '%s' not found in labelled namespace '%s' - creating", c.caBundleConfigMapName, key)

			secret, err := c.kubeclientset.CoreV1().Secrets(c.caBundleSecretNamespaceName).Get(c.caBundleSecretName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			_, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Create(newConfigMap)
			if err != nil {
				return err
			}
			return nil
		}

		return err
	}

	if cm != nil {
		log.Debugf("configmap '%s' exists in namespace '%s' with old ca bundle - updating", c.caBundleConfigMapName, key)
		secret, err := c.kubeclientset.CoreV1().Secrets(c.caBundleSecretNamespaceName).Get(c.caBundleSecretName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
		_, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Update(newConfigMap)
		if err != nil {
			return err
		}
	}

	c.recorder.Event(cm, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

//syncHandler for changed namespaces
func (c *Controller) syncHandlerChangedNamespace(key string) error {
	ns, err := c.namespaceLister.Get(key)
	if err != nil {
		return err
	}

	log.Debugf("Looking for configmap '%s' in labelled namespace '%s'", c.caBundleConfigMapName, ns.Name)
	cm, err := c.configMapLister.ConfigMaps(ns.Name).Get(c.caBundleConfigMapName)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Debugf("configmap '%s' not found in updated namespace '%s' - creating", c.caBundleConfigMapName, key)
			secret, err := c.kubeclientset.CoreV1().Secrets(c.caBundleSecretNamespaceName).Get(c.caBundleSecretName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			_, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Create(newConfigMap)
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}

	//If the resource exists in a non-labelled namespace, we delete it
	if !c.isNamespacesLabelled(ns) && cm != nil {
		log.Infof("configmap '%s' exists in namespace '%s' which is no longer labelled to keep CA Bundle", c.caBundleConfigMapName, key)
		err = c.kubeclientset.CoreV1().ConfigMaps(key).Delete(c.caBundleConfigMapName, &metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) isNamespacesLabelled(ns *corev1.Namespace) bool {
	lbl := ns.Labels[c.labelName]
	if lbl == "enabled" {
		return true
	}

	return false
}

func newConfigMap(name string, ns string, secret *corev1.Secret) *corev1.ConfigMap {
	dataByte := secret.Data["ca.crt"]
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(secret, schema.GroupVersionKind{
					Group:   corev1.SchemeGroupVersion.Group,
					Version: corev1.SchemeGroupVersion.Version,
					Kind:    "Secret",
				}),
			},
		},
		Data: map[string]string{
			"caCert": string(dataByte),
		},
	}
}

// enqueueSecret takes a Secret resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Secret.
func (c *Controller) enqueueSecret(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.secretWorkqueue.AddRateLimited(key)
}

// enqueueNamespace takes a Namespace resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Namespace.
func (c *Controller) enqueueNewNamespace(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.newNamespaceWorkqueue.AddRateLimited(key)
}

// enqueueNamespace takes a Namespace resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Namespace.
func (c *Controller) enqueueChangedNamespace(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.changedNamespaceWorkqueue.AddRateLimited(key)
}

// // enqueueAzurePoll takes a AzureKeyVaultSecret resource and converts it into a namespace/name
// // string which is then put onto the work queue. This method should *not* be
// // passed resources of any type other than AzureKeyVaultSecret.
// func (c *Controller) enqueueAzurePoll(obj interface{}) {
// 	var key string
// 	var err error
// 	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
// 		utilruntime.HandleError(err)
// 		return
// 	}
// 	c.workqueueAzure.AddRateLimited(key)
// }

// // dequeueAzureKeyVaultSecret takes a AzureKeyVaultSecret resource and converts it into a namespace/name
// // string which is then put onto the work queue for deltion. This method should *not* be
// // passed resources of any type other than AzureKeyVaultSecret.
// func (c *Controller) enqueueDeleteAzureKeyVaultSecret(obj interface{}) {
// 	var key string
// 	var err error

// 	if key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err != nil {
// 		utilruntime.HandleError(err)
// 		return
// 	}
// 	c.workqueue.AddRateLimited(key)

// 	// Getting default key to remove from Azure work queue
// 	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
// 		utilruntime.HandleError(err)
// 		return
// 	}
// 	c.workqueueAzure.Forget(key)
// }
