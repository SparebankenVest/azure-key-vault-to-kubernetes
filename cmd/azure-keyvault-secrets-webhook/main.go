// Copyright © 2020 Sparebanken Vest
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Note: Code is based on bank-vaults from Banzai Cloud
//       (https://github.com/banzaicloud/bank-vaults)

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	whhttp "github.com/slok/kubewebhook/pkg/http"
	internalLog "github.com/slok/kubewebhook/pkg/log"
	"github.com/slok/kubewebhook/pkg/observability/metrics"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"
	"github.com/spf13/viper"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	dockerHubHost      = "index.docker.io"
	oldDockerHubHost   = "docker.io"
	injectorDir        = "/azure-keyvault/"
	injectorExecutable = "azure-keyvault-env"
	clientCertDir      = "/client-cert/"
)

type azureKeyVaultConfig struct {
	port                string
	caPort              string
	customAuth          bool
	namespace           string
	aadPodBindingLabel  string
	dockerPullTimeout   int
	cloudConfigHostPath string
	serveMetrics        bool
	metricsPort         string
	certFile            string
	keyFile             string
	caFile              string
	useAuthService      bool
	// nameLocallyOverrideAuthService string
	authServiceName string
	authServicePort string
	kubeClient      *kubernetes.Clientset
	credentials     vault.AzureKeyVaultCredentials
}

var config azureKeyVaultConfig

var (
	podsMutatedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_pod_mutations_total",
		Help: "The total number of pods mutated",
	})
)

var (
	podsInspectedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_pod_inspections_total",
		Help: "The total number of pods inspected, including mutated",
	})
)

var (
	podsMutatedFailedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_pod_mutations_failed_total",
		Help: "The total number of attempted pod mutations that failed",
	})
)

const envVarReplacementKey = "@azurekeyvault"

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

func vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	req := whcontext.GetAdmissionRequest(ctx)
	config.namespace = req.Namespace
	var pod *corev1.Pod

	switch v := obj.(type) {
	case *corev1.Pod:
		log.Infof("found pod to mutate in namespace '%s'", config.namespace)
		pod = v
	default:
		return false, nil
	}

	podsInspectedCounter.Inc()
	err := mutatePodSpec(pod)

	if err != nil {
		podsMutatedFailedCounter.Inc()
	}

	return false, err
}

func initConfig() {
	viper.SetDefault("azurekeyvault_env_image", "spvest/azure-keyvault-env:latest")
	viper.SetDefault("custom_docker_pull_timeout", 20)
	viper.SetDefault("use_auth_service", true)
	viper.SetDefault("cloud_config_host_path", "/etc/kubernetes/azure.json")
	viper.SetDefault("metrics_port", "80")
	viper.SetDefault("port", "443")

	viper.AutomaticEnv()
}

func handlerFor(config mutating.WebhookConfig, mutator mutating.MutatorFunc, recorder metrics.Recorder, logger internalLog.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config, mutator, nil, nil, logger)
	if err != nil {
		log.Errorf("error creating webhook: %s", err)
		os.Exit(1)
	}

	handler, err := whhttp.HandlerFor(webhook)
	if err != nil {
		log.Errorf("error creating webhook: %s", err)
		os.Exit(1)
	}

	return handler
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		vars := mux.Vars(r)
		pod := podData{
			name:          vars["namespace"],
			namespace:     vars["pod"],
			remoteAddress: r.RemoteAddr,
		}

		if pod.name == "" || pod.namespace == "" {
			log.Errorf("failed to parse url parameters, pod='%s', namespace='%s'", pod.name, pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		err := authorize(config.kubeClient, pod)

		if err != nil {
			log.Errorf("failed to authorize request: %+v", err)
			http.Error(w, "", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)

		log.Infof("served oauth token to '%s/%s' at address '%s'", pod.namespace, pod.name, r.RemoteAddr)

		if err := json.NewEncoder(w).Encode(config.credentials); err != nil {
			log.Errorf("failed to json encode token, error: %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		log.Error("invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		caCert, err := ioutil.ReadFile(config.caFile)
		if err != nil {
			log.Fatal(err)
		}
		w.Write(caCert)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func serveCA() {
	log.Infof("CA cert at http://%s:", config.metricsPort)

	caMux := http.NewServeMux()
	caMux.HandleFunc("/ca", handleCACert)
	err := http.ListenAndServe(fmt.Sprintf(":%s", config.caPort), caMux)
	if err != nil {
		log.Fatalf("error serving ca cert: %s", err)
	}
}

func main() {
	fmt.Fprintln(os.Stdout, "initializing config...")
	initConfig()
	fmt.Fprintln(os.Stdout, "config initialized")

	logLevel := viper.GetString("LOG_LEVEL")
	setLogLevel(logLevel)

	config = azureKeyVaultConfig{
		port:                viper.GetString("port"),
		customAuth:          viper.GetBool("custom_auth"),
		dockerPullTimeout:   viper.GetInt("custom_docker_pull_timeout"),
		serveMetrics:        viper.GetBool("metrics_enabled"),
		metricsPort:         viper.GetString("metrics_port"),
		certFile:            viper.GetString("tls_cert_file"),
		keyFile:             viper.GetString("tls_private_key_file"),
		caFile:              viper.GetString("tls_ca_file"),
		useAuthService:      viper.GetBool("use_auth_service"),
		authServiceName:     viper.GetString("webhook_auth_service"),
		authServicePort:     viper.GetString("webhook_auth_service_port"),
		cloudConfigHostPath: viper.GetString("cloud_config_host_path"),
	}

	mutator := mutating.MutatorFunc(vaultSecretsMutator)
	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)

	internalLogger := &internalLog.Std{Debug: logLevel == "debug" || logLevel == "trace"}
	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, internalLogger)

	var err error
	if config.customAuth {
		config.credentials, err = vault.NewAzureKeyVaultCredentialsFromEnvironment()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		config.credentials, err = vault.NewAzureKeyVaultCredentialsFromCloudConfig(config.cloudConfigHostPath)
		if err != nil {
			log.Fatal(err)
		}
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to get kubernetes in cluster config, error: %+v", err)
	}

	config.kubeClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	log.Infof("Serving unencrypted traffic at http://:%s", config.metricsPort)

	httpMux := http.NewServeMux()
	if config.serveMetrics {
		httpMux.Handle("/metrics", promhttp.Handler())
	}
	httpMux.HandleFunc("/ca", handleCACert)
	httpMux.HandleFunc("/healthz", healthHandler)

	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%s", config.metricsPort), httpMux)
		if err != nil {
			log.Fatalf("error serving on port %s: %s", config.metricsPort, err)
		}
	}()

	router := mux.NewRouter()
	router.Handle("/pods", podHandler)
	router.HandleFunc("/auth/{namespace}/{pod}", authHandler)
	router.HandleFunc("/healthz", healthHandler)

	log.Infof("Serving TLS encrypted traffic at https://:%s", config.port)
	err = http.ListenAndServeTLS(fmt.Sprintf(":%s", config.port), config.certFile, config.keyFile, router)
	if err != nil {
		log.Fatalf("error serving webhook: %+v", err)
	}
}
