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
	"fmt"
	"net/http"
	"os"

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
)

const (
	dockerHubHost      = "index.docker.io"
	oldDockerHubHost   = "docker.io"
	injectorDir        = "/azure-keyvault/"
	injectorExecutable = "azure-keyvault-env"
	clientCertDir      = "/client-cert/"
)

type azureKeyVaultConfig struct {
	namespace                      string
	aadPodBindingLabel             string
	dockerPullTimeout              int
	cloudConfigHostPath            string
	serveMetrics                   bool
	metricsAddress                 string
	certFile                       string
	keyFile                        string
	caFile                         string
	clientCertFile                 string
	clientKeyFile                  string
	clientCertSecretName           string
	useAuthService                 bool
	nameLocallyOverrideAuthService string
	authServiceName                string
	authServicePort                string
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
	viper.SetDefault("custom_docker_pull_timeout", 120)
	viper.SetDefault("client_cert_secret_name", "akv2k8s-client-cert")
	viper.SetDefault("use_auth_service", true)
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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func serveMetrics() {
	log.Infof("Metrics at http://%s", config.metricsAddress)

	metricMux := http.NewServeMux()
	metricMux.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(config.metricsAddress, metricMux)
	if err != nil {
		log.Fatalf("error serving metrics: %s", err)
	}
}

func main() {
	fmt.Fprintln(os.Stdout, "initializing config...")
	initConfig()
	fmt.Fprintln(os.Stdout, "config initialized")

	logLevel := viper.GetString("LOG_LEVEL")
	setLogLevel(logLevel)

	config = azureKeyVaultConfig{
		dockerPullTimeout:    viper.GetInt("custom_docker_pull_timeout"),
		serveMetrics:         viper.GetBool("metrics_enabled"),
		metricsAddress:       viper.GetString("metrics_addr"),
		certFile:             viper.GetString("tls_cert_file"),
		keyFile:              viper.GetString("tls_private_key_file"),
		caFile:               viper.GetString("tls_ca_file"),
		clientCertFile:       viper.GetString("tls_client_file"),
		clientKeyFile:        viper.GetString("tls_client_key_file"),
		clientCertSecretName: viper.GetString("client_cert_secret_name"),
		useAuthService:       viper.GetBool("use_auth_service"),
		authServiceName:      viper.GetString("webhook_auth_service"),
		authServicePort:      viper.GetString("webhook_auth_service_port"),
		cloudConfigHostPath:  viper.GetString("cloud_config_host_path"),
	}

	if config.metricsAddress == "" {
		config.metricsAddress = ":80"
	}

	mutator := mutating.MutatorFunc(vaultSecretsMutator)
	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)

	internalLogger := &internalLog.Std{Debug: logLevel == "debug" || logLevel == "trace"}
	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, internalLogger)

	if config.serveMetrics {
		go serveMetrics()
	}

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)
	mux.HandleFunc("/healthz", healthHandler)

	log.Infof("listening on :443")
	err := http.ListenAndServeTLS(":443", config.certFile, config.keyFile, mux)
	if err != nil {
		log.Fatalf("error serving webhook: %+v", err)
	}
}
