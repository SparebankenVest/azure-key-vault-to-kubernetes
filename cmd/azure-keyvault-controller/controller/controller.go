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
	listers "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/listers/azurekeyvault/v2beta1"
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

type NamespaceSelectorLabel struct {
	Name  string
	Value string
}

type CABundle struct {
	ConfigMapName   string
	SecretNamespace string
	SecretName      string
}

// Controller is the controller implementation for AzureKeyVaultSecret resources
type Controller struct {
	kubeclientset       kubernetes.Interface
	akvsClient          akvcs.Interface
	vaultService        vault.Service
	recorder            record.EventRecorder
	kubeInformerFactory informers.SharedInformerFactory
	namespaceAkvsLabel  string

	// Secret
	secretsLister corelisters.SecretLister

	// ConfigMap
	configMapsLister corelisters.ConfigMapLister

	// AzureKeyVaultSecret
	azureKeyVaultSecretLister listers.AzureKeyVaultSecretLister
	akvsInformerFactory       akvInformers.SharedInformerFactory
	akvsCrdQueue              *queue.Worker
	akvsCrdDeletionQueue      *queue.Worker
	azureKeyVaultQueue        *queue.Worker

	options *Options
	clock   Timer

	akvLogger *log.Entry
}

// Options contains options for the controller
type Options struct {
	NumThreads     int
	MaxNumRequeues int
	ResyncPeriod   time.Duration
	AkvsRef        corev1.ObjectReference
}

// NewController returns a new AzureKeyVaultSecret controller
func NewController(client kubernetes.Interface, akvsClient akvcs.Interface, akvInformerFactory akvInformers.SharedInformerFactory, kubeInformerFactory informers.SharedInformerFactory, recorder record.EventRecorder, vaultService vault.Service, options *Options) *Controller {
	// Create event broadcaster
	// Add azure-keyvault-controller types to the default Kubernetes Scheme so Events can be
	// logged for azure-keyvault-controller types.
	utilruntime.Must(keyvaultScheme.AddToScheme(scheme.Scheme))

	akvLogger := log.WithFields(log.Fields{"component": "akvs"})

	controller := &Controller{
		kubeclientset: client,
		akvsClient:    akvsClient,
		recorder:      recorder,
		vaultService:  vaultService,

		akvsInformerFactory: akvInformerFactory,
		kubeInformerFactory: kubeInformerFactory,

		secretsLister:             kubeInformerFactory.Core().V1().Secrets().Lister(),
		configMapsLister:          kubeInformerFactory.Core().V1().ConfigMaps().Lister(),
		azureKeyVaultSecretLister: akvInformerFactory.Keyvault().V2beta1().AzureKeyVaultSecrets().Lister(),

		options: options,
		clock:   &Clock{},

		akvLogger: akvLogger,
	}

	controller.akvsCrdQueue = queue.New("AzureKeyVaultSecrets", options.MaxNumRequeues, options.NumThreads, controller.syncAzureKeyVaultSecret)
	controller.akvsCrdDeletionQueue = queue.New("DeletedAzureKeyVaultSecrets", options.MaxNumRequeues, options.NumThreads, controller.syncDeletedAzureKeyVaultSecret)
	controller.azureKeyVaultQueue = queue.New("AzureKeyVault", options.MaxNumRequeues, options.NumThreads, controller.syncAzureKeyVault)

	log.Info("Setting up event handlers")
	controller.initAzureKeyVaultSecret()

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

	log.Info("starting azure key vault deleted secret queue")
	c.akvsCrdDeletionQueue.Run(stopCh)

	log.Info("starting azure key vault queue")
	c.azureKeyVaultQueue.Run(stopCh)

	log.Info("started workers")
	<-stopCh
	log.Info("Shutting down workers")
}
