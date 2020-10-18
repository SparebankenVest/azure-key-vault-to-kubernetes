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
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	corev1 "k8s.io/api/core/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"

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
	viper.SetDefault("version", "dev")
	viper.SetDefault("log_format", "fmt")
	viper.SetDefault("cloudconfig", "/etc/kubernetes/azure.json")
	viper.SetDefault("custom_auth", false)

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

	akv2k8s.Version = viper.GetString("version")

	setLogLevel(viper.GetString("log_level"))
	setLogFormat(viper.GetString("log_format"))

	akv2k8s.LogVersion()

	// kubeconfig := viper.GetString("kubeconfig")
	// masterURL := viper.GetString("master")
	// cloudconfig := viper.GetString("cloudconfig")

	customAuth := viper.GetBool("custom_auth")

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	azureKeyVaultSecretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error building azureKeyVaultSecret clientset: %s", err.Error())
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)
	azureKeyVaultSecretInformerFactory := informers.NewSharedInformerFactory(azureKeyVaultSecretClient, time.Second*30)

	log.Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Tracef)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	var vaultAuth *credentialprovider.AzureKeyVaultCredentials
	if customAuth {
		provider, err := credentialprovider.NewFromEnvironment()
		if err != nil {
			log.Fatalf("failed to create azure credentials provider, error: %+v", err.Error())
		}

		if vaultAuth, err = provider.GetAzureKeyVaultCredentials(); err != nil {
			log.Fatalf("failed to get azure key vault credentials, error: %+v", err.Error())
		}
	} else {
		f, err := os.Open(cloudconfig)
		if err != nil {
			log.Fatalf("Failed reading azure config from %s, error: %+v", cloudconfig, err)
		}
		defer f.Close()

		cloudCnfProvider, err := credentialprovider.NewFromCloudConfig(f)
		if err != nil {
			log.Fatalf("Failed reading azure config from %s, error: %+v", cloudconfig, err)
		}

		if vaultAuth, err = cloudCnfProvider.GetAzureKeyVaultCredentials(); err != nil {
			log.Fatalf("failed to create azure key vault credentials, error: %+v", err.Error())
		}
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

func setLogFormat(logFormat string) {
	switch logFormat {
	case "fmt":
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.Warnf("Log format %s not supported - using default fmt", logFormat)
	}
}

func setLogLevel(logLevel string) {
	if logLevel == "" {
		logLevel = log.InfoLevel.String()
	}

	logrusLevel, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("error setting log level: %s", err.Error())
	}
	log.SetLevel(logrusLevel)
}
