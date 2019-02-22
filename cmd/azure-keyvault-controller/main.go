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
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/cmd/azure-keyvault-controller/controller"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/client/clientset/versioned"
	informers "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/client/informers/externalversions"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/signals"
)

var (
	masterURL  string
	kubeconfig string
	logLevel   string

	azureVaultFastRate        time.Duration
	azureVaultSlowRate        time.Duration
	azureVaultMaxFastAttempts int
)

const controllerAgentName = "azurekeyvaultcontroller"

func main() {
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()
	setLogLevel()

	var err error
	azureVaultFastRate, err = getEnvDuration("AZURE_VAULT_NORMAL_POLL_INTERVALS", time.Minute*1)
	if err != nil {
		log.Fatalf("Error parsing env var AZURE_VAULT_NORMAL_POLL_INTERVALS: %s", err.Error())
	}

	azureVaultSlowRate, err = getEnvDuration("AZURE_VAULT_EXCEPTION_POLL_INTERVALS", time.Minute*5)
	if err != nil {
		log.Fatalf("Error parsing env var AZURE_VAULT_EXCEPTION_POLL_INTERVALS: %s", err.Error())
	}

	azureVaultMaxFastAttempts, err = getEnvInt("AZURE_VAULT_MAX_FAILURE_ATTEMPTS", 5)
	if err != nil {
		log.Fatalf("Error parsing env var AZURE_VAULT_MAX_FAILURE_ATTEMPTS: %s", err.Error())
	}

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
	azurePollFrequency := controller.AzurePollFrequency{
		Normal:                       azureVaultFastRate,
		Slow:                         azureVaultSlowRate,
		MaxFailuresBeforeSlowingDown: azureVaultMaxFastAttempts,
	}

	log.Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Tracef)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	vaultService := vault.NewService()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})
	handler := controller.NewHandler(kubeClient, azureKeyVaultSecretClient, kubeInformerFactory.Core().V1().Secrets().Lister(), azureKeyVaultSecretInformerFactory.Azurekeyvaultcontroller().V1alpha1().AzureKeyVaultSecrets().Lister(), recorder, vaultService, azurePollFrequency)

	controller := controller.NewController(handler,
		kubeInformerFactory.Core().V1().Secrets(),
		azureKeyVaultSecretInformerFactory.Azurekeyvaultcontroller().V1alpha1().AzureKeyVaultSecrets(),
		azurePollFrequency)

	// notice that there is no need to run Start methods in a separate goroutine. (i.e. go kubeInformerFactory.Start(stopCh)
	// Start method is non-blocking and runs all registered informers in a dedicated goroutine.
	kubeInformerFactory.Start(stopCh)
	azureKeyVaultSecretInformerFactory.Start(stopCh)

	if err = controller.Run(2, stopCh); err != nil {
		log.Fatalf("Error running controller: %s", err.Error())
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&logLevel, "log-level", "", "log level")
}

func setLogLevel() {
	if logLevel == "" {
		var ok bool
		if logLevel, ok = os.LookupEnv("LOG_LEVEL"); !ok {
			logLevel = log.InfoLevel.String()
		}
	}

	logrusLevel, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Error setting log level: %s", err.Error())
	}
	log.SetLevel(logrusLevel)
	log.Printf("Log level set to '%s'", logrusLevel.String())
}

func getEnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	if value, ok := os.LookupEnv(key); ok {
		duration, err := time.ParseDuration(value)
		return duration, err
	}
	return fallback, nil
}

func getEnvInt(key string, fallback int) (int, error) {
	if value, ok := os.LookupEnv(key); ok {
		intVal, err := strconv.Atoi(value)
		return intVal, err
	}
	return fallback, nil
}
