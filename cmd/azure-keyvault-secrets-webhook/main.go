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
	"net/http"
	"os"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
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
	dockerHubHost           = "index.docker.io"
	oldDockerHubHost        = "docker.io"
	injectorDir             = "/azure-keyvault/"
	injectorExecutable      = "azure-keyvault-env"
	clientCertDir           = "/client-cert/"
	initContainerVolumeName = "azure-keyvault-env"
)

type azureKeyVaultConfig struct {
	port       string
	customAuth bool
	namespace  string
	// aadPodBindingLabel  string
	cloudConfigHostPath string
	serveMetrics        bool
	httpPort            string
	certFile            string
	keyFile             string
	caFile              string
	useAuthService      bool
	// nameLocallyOverrideAuthService string
	dockerImageInspectionTimeout int
	authServiceName              string
	authServicePort              string
	caBundleConfigMapName        string
	kubeClient                   *kubernetes.Clientset
	credentials                  azure.Credentials
}

var config azureKeyVaultConfig

var (
	podsMutatedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_pod_mutations_total",
		Help: "The total number of pods mutated",
	})

	podsInspectedCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_pod_inspections_total",
		Help: "The total number of pods inspected, including mutated",
	})

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
		log.Errorf("failed to mutate pod, error: %+v", err)
		podsMutatedFailedCounter.Inc()
	}

	return false, err
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
			name:          vars["pod"],
			namespace:     vars["namespace"],
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

func initConfig() {
	viper.SetDefault("ca_config_map_name", "akv2k8s-ca")
	viper.SetDefault("azurekeyvault_env_image", "spvest/azure-keyvault-env:latest")
	viper.SetDefault("docker_image_inspection_timeout", 20)
	viper.SetDefault("use_auth_service", true)
	viper.SetDefault("cloud_config_host_path", "/etc/kubernetes/azure.json")
	viper.SetDefault("metrics_enabled", false)
	viper.SetDefault("port_http", "80")
	viper.SetDefault("port", "443")

	viper.AutomaticEnv()
}

func main() {
	fmt.Fprintln(os.Stdout, "initializing config...")
	initConfig()
	fmt.Fprintln(os.Stdout, "config initialized")

	logLevel := viper.GetString("LOG_LEVEL")
	setLogLevel(logLevel)

	config = azureKeyVaultConfig{
		port:                         viper.GetString("port"),
		httpPort:                     viper.GetString("port_http"),
		customAuth:                   viper.GetBool("custom_auth"),
		serveMetrics:                 viper.GetBool("metrics_enabled"),
		certFile:                     viper.GetString("tls_cert_file"),
		keyFile:                      viper.GetString("tls_private_key_file"),
		caFile:                       viper.GetString("tls_ca_file"),
		useAuthService:               viper.GetBool("use_auth_service"),
		authServiceName:              viper.GetString("webhook_auth_service"),
		authServicePort:              viper.GetString("webhook_auth_service_port"),
		caBundleConfigMapName:        viper.GetString("ca_config_map_name"),
		cloudConfigHostPath:          viper.GetString("cloud_config_host_path"),
		dockerImageInspectionTimeout: viper.GetInt("docker_image_inspection_timeout"),
	}

	log.Info("Active settings:")
	log.Infof("Webhook port       : %s", config.port)
	log.Infof("Serve metrics      : %t", config.serveMetrics)
	log.Infof("Use custom auth    : %t", config.customAuth)
	log.Infof("Use auth service   : %t", config.useAuthService)
	if config.useAuthService {
		log.Infof("Auth service name  : %s", config.authServiceName)
		log.Infof("Auth service port  :%s", config.authServicePort)
	}
	log.Infof("CA ConfigMap name  : %s", config.caBundleConfigMapName)
	log.Infof("Cloud config path  : %s", config.cloudConfigHostPath)

	mutator := mutating.MutatorFunc(vaultSecretsMutator)
	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)

	internalLogger := &internalLog.Std{Debug: logLevel == "debug" || logLevel == "trace"}
	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, internalLogger)

	var err error
	if config.customAuth {
		config.credentials, err = azure.NewFromEnvironment()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		f, err := os.Open(config.cloudConfigHostPath)
		if err != nil {
			log.Fatalf("Failed reading azure config from %s, error: %+v", config.cloudConfigHostPath, err)
		}
		defer f.Close()

		cloudCnfProvider, err := azure.NewFromCloudConfig(f)
		if err != nil {
			log.Fatalf("Failed reading azure config from %s, error: %+v", config.cloudConfigHostPath, err)
		}

		config.credentials, err = cloudCnfProvider.GetCredentials()
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

	httpMux := http.NewServeMux()
	httpURL := fmt.Sprintf(":%s", config.httpPort)

	if config.serveMetrics {
		httpMux.Handle("/metrics", promhttp.Handler())
		log.Infof("Serving metrics at %s/metrics", httpURL)
	}
	httpMux.HandleFunc("/healthz", healthHandler)
	log.Infof("Serving healthz at %s/healthz", httpURL)

	go func() {

		err := http.ListenAndServe(httpURL, httpMux)
		if err != nil {
			log.Fatalf("error serving metrics at %s: %+v", httpURL, err)
		}
	}()

	router := mux.NewRouter()
	tlsURL := fmt.Sprintf(":%s", config.port)

	router.Handle("/pods", podHandler)
	log.Infof("Serving encrypted webhook at %s/pods", tlsURL)

	router.HandleFunc("/healthz", healthHandler)
	log.Infof("Serving encrypted healthz at %s/healthz", tlsURL)

	if config.useAuthService {
		router.HandleFunc("/auth/{namespace}/{pod}", authHandler)
		log.Infof("Serving encrypted auth at %s/auth", tlsURL)
	}

	err = http.ListenAndServeTLS(tlsURL, config.certFile, config.keyFile, router)
	if err != nil {
		log.Fatalf("error serving webhook: %+v", err)
	}
}
