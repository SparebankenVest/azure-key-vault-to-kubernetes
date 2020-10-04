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

	// MessageResourceSynced is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully
	MessageResourceSynced = "AzureKeyVaultSecret synced successfully"

	// MessageResourceSyncedWithAzure is the message used for an Event fired when a AzureKeyVaultSecret
	// is synced successfully after getting updated secret from Azure Key Vault
	MessageResourceSyncedWithAzure = "AzureKeyVaultSecret synced successfully with Azure Key Vault"
)

// Controller is the controller implementation for AzureKeyVaultSecret resources
type Controller struct {
	kubeclientset kubernetes.Interface
	akvsClient    akvcs.Interface
	vaultService  vault.Service
	recorder      record.EventRecorder

	// Secret
	secretsLister         corelisters.SecretLister
	secretInformerFactory informers.SharedInformerFactory
	akvsSecretQueue       *queue.Worker

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
	namespaceLister          corelisters.NamespaceLister
	namespaceInformerFactory informers.SharedInformerFactory
	namespaceQueue           *queue.Worker

	// ConfigMap
	configMapLister          corelisters.ConfigMapLister
	configMapInformerFactory informers.SharedInformerFactory
	configMapQueue           *queue.Worker

	options *Options
	clock   Timer
}

// Options contains options for the controller
type Options struct {
	NumThreads         int
	MaxNumRequeues     int
	ResyncPeriod       time.Duration
	AkvsRef            corev1.ObjectReference
	NamespaceAkvsLabel string
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
func NewController(client kubernetes.Interface, akvsClient akvcs.Interface, akvInformerFactory akvInformers.SharedInformerFactory, secretInformerFactory informers.SharedInformerFactory, recorder record.EventRecorder, vaultService vault.Service, azureFrequency AzurePollFrequency, options *Options) *Controller {
	// Create event broadcaster
	// Add azure-keyvault-controller types to the default Kubernetes Scheme so Events can be
	// logged for azure-keyvault-controller types.
	utilruntime.Must(keyvaultScheme.AddToScheme(scheme.Scheme))

	controller := &Controller{
		kubeclientset: client,
		akvsClient:    akvsClient,
		recorder:      recorder,
		vaultService:  vaultService,

		akvsInformerFactory:   akvInformerFactory,
		secretInformerFactory: secretInformerFactory,

		secretsLister:             secretInformerFactory.Core().V1().Secrets().Lister(),
		azureKeyVaultSecretLister: akvInformerFactory.Azurekeyvault().V2alpha1().AzureKeyVaultSecrets().Lister(),

		options: options,
		clock:   &Clock{},
	}

	controller.akvsCrdQueue = queue.New("AzureKeyVaultSecrets", options.MaxNumRequeues, options.NumThreads, controller.syncAzureKeyVaultSecret)
	controller.akvsSecretQueue = queue.New("Secrets", options.MaxNumRequeues, options.NumThreads, controller.syncSecret)
	controller.azureKeyVaultQueue = queue.New("AzureKeyVault", options.MaxNumRequeues, options.NumThreads, controller.syncAzureKeyVault)
	controller.caBundleSecretQueue = queue.New("CABundleSecrets", options.MaxNumRequeues, options.NumThreads, controller.syncCABundleSecret)

	log.Info("Setting up event handlers")
	controller.initAzureKeyVaultSecret()
	controller.initSecret()

	return controller
}

// Run will start the controller
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	// Start the informer factories to begin populating the informer caches
	log.Info("Starting AzureKeyVaultSecret controller")
	c.akvsInformerFactory.Start(stopCh)
	c.secretInformerFactory.Start(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	for _, v := range c.akvsInformerFactory.WaitForCacheSync(stopCh) {
		if !v {
			runtime.HandleError(errors.Errorf("timed out waiting for caches to sync"))
			return
		}
	}
	for _, v := range c.secretInformerFactory.WaitForCacheSync(stopCh) {
		if !v {
			runtime.HandleError(errors.Errorf("timed out waiting for caches to sync"))
			return
		}
	}

	log.Debug("Starting Azure Key Vault Secret queue")
	c.akvsCrdQueue.Run(stopCh)

	log.Debug("Starting Secret queue for Azure Key Vault Secrets")
	c.akvsSecretQueue.Run(stopCh)

	log.Debug("Starting Azure Key Vault queue")
	c.azureKeyVaultQueue.Run(stopCh)

	log.Info("Started workers")
	<-stopCh
	log.Info("Shutting down workers")
}
