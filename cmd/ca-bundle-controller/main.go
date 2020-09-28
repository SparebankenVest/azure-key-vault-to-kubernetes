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

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/controller/cabundleinjector"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/signals"
	"github.com/spf13/viper"
)

var (
	masterURL   string
	kubeconfig  string
	cloudconfig string
	logLevel    string
	logFormat   string

	azureVaultFastRate        time.Duration
	azureVaultSlowRate        time.Duration
	azureVaultMaxFastAttempts int
	customAuth                bool
)

const controllerAgentName = "ca-bundle-controller"

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

func initConfig() {
	viper.SetDefault("akv_label_name", "azure-key-vault-env-injection")
	viper.SetDefault("ca_config_map_name", "akv2k8s-ca")
	viper.SetDefault("cloudconfig", "/etc/kubernetes/azure.json")
	viper.AutomaticEnv()
}

func main() {
	initConfig()

	logLevel := viper.GetString("log_level")
	setLogLevel(logLevel)

	logFormat := viper.GetString("log_format")
	setLogFormat(logFormat)

	akv2k8s.Version = viper.GetString("version")

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	akvLabelName := viper.GetString("akv_label_name")
	akvNamespace := viper.GetString("akv_namespace")

	if akvNamespace == "" {
		log.Fatal("Env var AKV_NAMESPACE is required")
	}

	akvSecretName := viper.GetString("akv_secret_name")
	if akvSecretName == "" {
		log.Fatal("Env var AKV_SECRET_NAME is required")
	}

	kubeconfig = viper.GetString("kubeconfig")
	masterURL = viper.GetString("master")
	cloudconfig = viper.GetString("cloudconfig")

	caConfigMapName := viper.GetString("ca_config_map_name")

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)
	kubeNsInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, time.Second*30, kubeinformers.WithNamespace(akvNamespace))

	log.Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Tracef)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := cabundleinjector.NewController(kubeClient, recorder, kubeNsInformerFactory.Core().V1().Secrets(), kubeInformerFactory.Core().V1().Namespaces(), kubeInformerFactory.Core().V1().ConfigMaps(), akvLabelName, akvNamespace, akvSecretName, caConfigMapName)

	// notice that there is no need to run Start methods in a separate goroutine. (i.e. go kubeInformerFactory.Start(stopCh)
	// Start method is non-blocking and runs all registered informers in a dedicated goroutine.
	kubeInformerFactory.Start(stopCh)
	kubeNsInformerFactory.Start(stopCh)

	if err = controller.Run(2, stopCh); err != nil {
		log.Fatalf("Error running controller: %s", err.Error())
	}
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

func getEnvStr(key string, fallback string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}
	return fallback, nil
}

func getEnvBool(key string, fallback bool) (bool, error) {
	if value, ok := os.LookupEnv(key); ok {
		if booVal, err := strconv.ParseBool(value); ok {
			return booVal, err
		}
	}
	return fallback, nil
}
