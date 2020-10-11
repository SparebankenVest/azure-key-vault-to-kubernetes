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
	"time"

	"github.com/appscode/go/runtime"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"
	"kmodules.xyz/client-go/tools/queue"

	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akvcs "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	keyvaultScheme "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned/scheme"
	akvInformers "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/informers/externalversions"
	listers "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/listers/azurekeyvault/v2alpha1"
)

const (
	// SuccessSynced is used as part of the Event 'reason' when a AzureKeyVaultSecret is synced
	SuccessSynced = "Synced"

	// ErrResourceExists is used as part of the Event 'reason' when a AzureKeyVaultSecret fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// ErrAzureVault is used as part of the Event 'reason' when a AzureKeyVaultSecret fails
	// to sync due to a Secret of the same name already existing.
	ErrAzureVault = "ErrAzureVault"

	// ErrConfigMap is used as part of the Event 'reason' when a Secret sync fails
	ErrConfigMap = "ErrConfigMap"

	// FailedAzureKeyVault is the message used for Events when a resource
	// fails to get secret from Azure Key Vault
	FailedAzureKeyVault = "Failed to get secret for '%s' from Azure Key Vault '%s'"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Deployment already existing
	MessageResourceExists = "Resource '%s' already exists and is not managed by AzureKeyVaultSecret"

	// MessageAzureKeyVaultSecretSynced is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully
	MessageAzureKeyVaultSecretSynced = "AzureKeyVaultSecret synced to Kubernetes Secret successfully"

	// MessageAzureKeyVaultSecretSyncedWithAzureKeyVault is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully after getting updated secret from Azure Key Vault
	MessageAzureKeyVaultSecretSyncedWithAzureKeyVault = "AzureKeyVaultSecret synced to Kubernetes Secret successfully with change from Azure Key Vault"

	ControllerName = "Akv2k8s controller"
)

// Controller is the controller implementation for AzureKeyVaultSecret resources
type Controller struct {
	kubeclientset       kubernetes.Interface
	akvsClient          akvcs.Interface
	vaultService        vault.Service
	recorder            record.EventRecorder
	kubeInformerFactory informers.SharedInformerFactory
	namespaceAkvsLabel  string

	// Secret
	secretsLister   corelisters.SecretLister
	akvsSecretQueue *queue.Worker

	// AzureKeyVaultSecret
	azureKeyVaultSecretLister listers.AzureKeyVaultSecretLister
	akvsInformerFactory       akvInformers.SharedInformerFactory
	akvsCrdQueue              *queue.Worker
	azureKeyVaultQueue        *queue.Worker

	// CA Bundle
	caBundleSecretQueue         *queue.Worker
	caBundleSecretName          string
	caBundleSecretNamespaceName string
	caBundleConfigMapName       string

	// Namespace
	namespaceLister corelisters.NamespaceLister
	namespaceQueue  *queue.Worker

	// ConfigMap
	configMapLister       corelisters.ConfigMapLister
	caBundleConigMapQueue *queue.Worker

	options *Options
	clock   Timer

	akvLogger      *log.Entry
	caBundleLogger *log.Entry
}

// Options contains options for the controller
type Options struct {
	NumThreads            int
	MaxNumRequeues        int
	ResyncPeriod          time.Duration
	AkvsRef               corev1.ObjectReference
	CABundleConfigMapName string
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

// NewController returns a new AzureKeyVaultSecret controller
func NewController(client kubernetes.Interface, akvsClient akvcs.Interface, akvInformerFactory akvInformers.SharedInformerFactory, kubeInformerFactory informers.SharedInformerFactory, recorder record.EventRecorder, vaultService vault.Service, caBundleSecretName, caBundleSecretNamespaceName, namespaceAkvsLabel string, azureFrequency AzurePollFrequency, options *Options) *Controller {
	// Create event broadcaster
	// Add azure-keyvault-controller types to the default Kubernetes Scheme so Events can be
	// logged for azure-keyvault-controller types.
	utilruntime.Must(keyvaultScheme.AddToScheme(scheme.Scheme))

	caBundleCMName := "caBundle"
	if options.CABundleConfigMapName != "" {
		caBundleCMName = options.CABundleConfigMapName
	}

	akvLogger := log.WithFields(log.Fields{"component": "akvs"})
	caBundleLogger := log.WithFields(log.Fields{"component": "caBundle"})

	controller := &Controller{
		kubeclientset:      client,
		akvsClient:         akvsClient,
		recorder:           recorder,
		vaultService:       vaultService,
		namespaceAkvsLabel: namespaceAkvsLabel,

		caBundleConfigMapName:       caBundleCMName,
		caBundleSecretName:          caBundleSecretName,
		caBundleSecretNamespaceName: caBundleSecretNamespaceName,

		akvsInformerFactory: akvInformerFactory,
		kubeInformerFactory: kubeInformerFactory,

		secretsLister:             kubeInformerFactory.Core().V1().Secrets().Lister(),
		azureKeyVaultSecretLister: akvInformerFactory.Keyvault().V2alpha1().AzureKeyVaultSecrets().Lister(),
		configMapLister:           kubeInformerFactory.Core().V1().ConfigMaps().Lister(),
		namespaceLister:           kubeInformerFactory.Core().V1().Namespaces().Lister(),

		options: options,
		clock:   &Clock{},

		akvLogger:      akvLogger,
		caBundleLogger: caBundleLogger,
	}

	controller.akvsCrdQueue = queue.New("AzureKeyVaultSecrets", options.MaxNumRequeues, options.NumThreads, controller.syncAzureKeyVaultSecret)
	controller.akvsSecretQueue = queue.New("Secrets", options.MaxNumRequeues, options.NumThreads, controller.syncSecret)
	controller.azureKeyVaultQueue = queue.New("AzureKeyVault", options.MaxNumRequeues, options.NumThreads, controller.syncAzureKeyVault)
	controller.caBundleSecretQueue = queue.New("CABundleSecrets", options.MaxNumRequeues, options.NumThreads, controller.syncCABundleSecret)
	controller.namespaceQueue = queue.New("Namespaces", options.MaxNumRequeues, options.NumThreads, controller.syncCABundleInNamespace)
	controller.caBundleConigMapQueue = queue.New("CABundleConfigs", options.MaxNumRequeues, options.NumThreads, controller.syncCABundleConfigMap)

	log.Info("Setting up event handlers")
	controller.initAzureKeyVaultSecret()
	controller.initSecret()
	controller.initNamespace()
	controller.initConfigMap()

	return controller
}

// Run will start the controller
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	// Start the informer factories to begin populating the informer caches
	log.Info("Starting AzureKeyVaultSecret controller")
	c.akvsInformerFactory.Start(stopCh)
	c.kubeInformerFactory.Start(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	for _, v := range c.akvsInformerFactory.WaitForCacheSync(stopCh) {
		if !v {
			runtime.HandleError(errors.Errorf("timed out waiting for caches to sync"))
			return
		}
	}
	for _, v := range c.kubeInformerFactory.WaitForCacheSync(stopCh) {
		if !v {
			runtime.HandleError(errors.Errorf("timed out waiting for caches to sync"))
			return
		}
	}

	log.Info("starting azure key vault secret queue")
	c.akvsCrdQueue.Run(stopCh)

	log.Info("starting secret queue for azure key vault secrets")
	c.akvsSecretQueue.Run(stopCh)

	log.Info("starting azure key vault queue")
	c.azureKeyVaultQueue.Run(stopCh)

	log.Info("starting ca bundle secret queue")
	c.caBundleSecretQueue.Run(stopCh)

	log.Info("starting ca bundle namespace queue")
	c.namespaceQueue.Run(stopCh)

	log.Info("starting ca bundle configmap queue")
	c.caBundleConigMapQueue.Run(stopCh)

	log.Info("started workers")
	<-stopCh
	log.Info("Shutting down workers")
}
