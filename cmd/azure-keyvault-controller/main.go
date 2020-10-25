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

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"

	corev1 "k8s.io/api/core/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/cmd/azure-keyvault-controller/controller"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	informers "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/informers/externalversions"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/signals"
)

const controllerAgentName = "azurekeyvaultcontroller"

var (
	version     string
	kubeconfig  string
	masterURL   string
	cloudconfig string
)

func initConfig() {
	viper.SetDefault("auth_type", "azureCloudConfig")

	viper.AutomaticEnv()
}

func init() {
	flag.StringVar(&version, "version", "", "Version of this component.")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&cloudconfig, "cloudconfig", "/etc/kubernetes/azure.json", "Path to cloud config. Only required if this is not at default location /etc/kubernetes/azure.json")
}

func main() {
	flag.Parse()
	initConfig()

	klog.InitFlags(nil)
	defer klog.Flush()

	akv2k8s.Version = version
	akv2k8s.LogVersion()

	authType := viper.GetString("auth_type")

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		klog.ErrorS(err, "failed to build kube config", "master", masterURL, "kubeconfig", kubeconfig)
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "failed to build kube clientset", "master", masterURL, "kubeconfig", kubeconfig)
		os.Exit(1)
	}

	azureKeyVaultSecretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "failed to build clientset for azurekeyvaultsecret", "master", masterURL, "kubeconfig", kubeconfig)
		os.Exit(1)
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)
	azureKeyVaultSecretInformerFactory := informers.NewSharedInformerFactory(azureKeyVaultSecretClient, time.Second*30)

	klog.V(2).InfoS("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.V(4).InfoS)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	var vaultAuth credentialprovider.AzureKeyVaultCredentials
	switch authType {
	case "azureCloudConfig":
		vaultAuth, err = getCredentialsFromCloudConfig(cloudconfig)
		if err != nil {
			klog.ErrorS(err, "failed to create cloud config provider for azure key vault", "file", cloudconfig)
			os.Exit(1)
		}
	case "environment":
		vaultAuth, err = getCredentialsFromEnvironment()
		if err != nil {
			klog.ErrorS(err, "failed to create credentials provider from environment for azure key vault")
			os.Exit(1)
		}
	default:
		klog.ErrorS(nil, "auth type not supported", "type", authType)
		os.Exit(1)
	}

	vaultService := vault.NewService(vaultAuth)
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	options := &controller.Options{
		MaxNumRequeues: 5,
		NumThreads:     1,
	}

	controller := controller.NewController(
		kubeClient,
		azureKeyVaultSecretClient,
		azureKeyVaultSecretInformerFactory,
		kubeInformerFactory,
		recorder,
		vaultService,
		options)

	controller.Run(stopCh)
}

func getCredentialsFromCloudConfig(cloudconfig string) (credentialprovider.AzureKeyVaultCredentials, error) {
	f, err := os.Open(cloudconfig)
	if err != nil {
		return nil, fmt.Errorf("failed reading azure config from %s, error: %+v", cloudconfig, err)
	}
	defer f.Close()

	cloudCnfProvider, err := credentialprovider.NewFromCloudConfig(f)
	if err != nil {
		return nil, fmt.Errorf("Failed reading azure config from %s, error: %+v", cloudconfig, err)
	}

	return cloudCnfProvider.GetAzureKeyVaultCredentials()
}

func getCredentialsFromEnvironment() (credentialprovider.AzureKeyVaultCredentials, error) {
	provider, err := credentialprovider.NewFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to create azure credentials provider, error: %+v", err)
	}

	return provider.GetAzureKeyVaultCredentials()
}
