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
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/cmd/azure-keyvault-secrets-webhook/auth"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/docker/registry"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	whhttp "github.com/slok/kubewebhook/pkg/http"
	internalLog "github.com/slok/kubewebhook/pkg/log"
	"github.com/slok/kubewebhook/pkg/observability/metrics"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"
	"github.com/spf13/viper"
	jsonlogs "k8s.io/component-base/logs/json"
	"k8s.io/klog/v2"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	dockerHubHost           = "index.docker.io"
	oldDockerHubHost        = "docker.io"
	injectorExecutable      = "azure-keyvault-env"
	clientCertDir           = "/var/client-cert/"
	initContainerVolumeName = "azure-keyvault-env"
)

type azureKeyVaultConfig struct {
	httpPort         string
	httpPortExternal string
	tlsPort          string
	tlsPortExternal  string
	mtlsPort         string
	mtlsPortExternal string

	cloudConfig  string
	serveMetrics bool
	tlsCertFile  string
	tlsKeyFile   string
	// caCert                       []byte
	// caKey                        []byte
	authType                     string
	useAuthService               bool
	authService                  *auth.AuthService
	dockerImageInspectionTimeout int
	authServiceName              string
	kubeClient                   kubernetes.Interface
	versionEnvImage              string
	kubeconfig                   string
	masterURL                    string
	injectorDir                  string
	credentials                  credentialprovider.Credentials
	credentialProvider           credentialprovider.CredentialProvider
	klogLevel                    int
	registry                     registry.ImageRegistry
}

type cmdParams struct {
	version         string
	versionEnvImage string
	kubeconfig      string
	masterURL       string
	cloudConfig     string
	logFormat       string
	logLevel        string
}

var config azureKeyVaultConfig
var params cmdParams

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

	containerImageInspectionCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_container_inspections_total",
		Help: "The total number of inspected container images",
	})

	containerImageInspectionFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_container_inspections_failed_total",
		Help: "The total number of failed container images inspections",
	})
)

const envVarReplacementKey = "@azurekeyvault"

func vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	req := whcontext.GetAdmissionRequest(ctx)
	var pod *corev1.Pod

	switch v := obj.(type) {
	case *corev1.Pod:
		klog.InfoS("found pod to mutate", "pod", klog.KRef(req.Namespace, req.Name))
		pod = v
	default:
		return false, nil
	}

	podsInspectedCounter.Inc()

	wh := podWebHook{
		clientset:                 config.kubeClient,
		namespace:                 req.Namespace,
		mutationID:                req.UID,
		injectorDir:               config.injectorDir,
		useAuthService:            config.useAuthService,
		authServiceName:           config.authServiceName,
		authServicePort:           config.mtlsPortExternal,
		authServiceValidationPort: config.httpPortExternal,
		authService:               config.authService,
		registry:                  config.registry,
	}

	err := wh.mutatePodSpec(context.Background(), pod)
	if err != nil {
		klog.ErrorS(err, "failed to mutate", "pod", klog.KRef(req.Namespace, req.Name))
		podsMutatedFailedCounter.Inc()
	}

	return false, err
}

func handlerFor(config mutating.WebhookConfig, mutator mutating.MutatorFunc, recorder metrics.Recorder, logger internalLog.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config, mutator, nil, recorder, logger)
	if err != nil {
		klog.ErrorS(err, "error creating webhook")
		os.Exit(1)
	}

	handler, err := whhttp.HandlerFor(webhook)
	if err != nil {
		klog.ErrorS(err, "error creating webhook")
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

func initConfig() {
	viper.SetDefault("http_port", "8080")
	viper.SetDefault("http_port_external", "80")
	viper.SetDefault("tls_port", "8443")
	viper.SetDefault("tls_port_external", "443")
	viper.SetDefault("mtls_port", "9443")
	viper.SetDefault("mtls_port_external", "9443")

	viper.SetDefault("azurekeyvault_env_image", "spvest/azure-keyvault-env:latest")
	viper.SetDefault("docker_image_inspection_timeout", 20)
	viper.SetDefault("docker_image_inspection_use_acs_credentials", true)
	viper.SetDefault("auth_type", "cloudConfig")
	viper.SetDefault("use_auth_service", true)
	viper.SetDefault("metrics_enabled", false)
	viper.SetDefault("env_injector_exec_dir", "/azure-keyvault/")
	viper.AutomaticEnv()
}

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	flag.StringVar(&params.version, "version", "", "Version of this component.")
	flag.StringVar(&params.versionEnvImage, "versionenvimage", "", "Version of the env image component.")
	// flag.StringVar(&params.kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	// flag.StringVar(&params.masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&params.cloudConfig, "cloudconfig", "/etc/kubernetes/azure.json", "Path to cloud config. Only required if this is not at default location /etc/kubernetes/azure.json")
	flag.StringVar(&params.logFormat, "logging-format", "text", "Log format - text or json.")

	flag.Parse()

	initConfig()

	if params.logFormat == "json" {
		klog.SetLogger(jsonlogs.JSONLogger)
	}

	akv2k8s.Version = params.version

	akv2k8s.LogVersion()

	config = azureKeyVaultConfig{
		httpPort:         viper.GetString("http_port"),
		httpPortExternal: viper.GetString("http_port_external"),
		tlsPort:          viper.GetString("tls_port"),
		tlsPortExternal:  viper.GetString("tls_port_external"),
		mtlsPortExternal: viper.GetString("mtls_port_external"),
		mtlsPort:         viper.GetString("mtls_port"),

		authType:                     viper.GetString("auth_type"),
		serveMetrics:                 viper.GetBool("metrics_enabled"),
		tlsCertFile:                  fmt.Sprintf("%s/%s", viper.GetString("tls_cert_dir"), "tls.crt"),
		tlsKeyFile:                   fmt.Sprintf("%s/%s", viper.GetString("tls_cert_dir"), "tls.key"),
		useAuthService:               viper.GetBool("use_auth_service"),
		authServiceName:              viper.GetString("webhook_auth_service"),
		dockerImageInspectionTimeout: viper.GetInt("docker_image_inspection_timeout"),
		injectorDir:                  viper.GetString("env_injector_exec_dir"),
		versionEnvImage:              params.versionEnvImage,
		cloudConfig:                  params.cloudConfig,
	}

	logLevel := flag.Lookup("v").Value.String()
	klogLevel, err := strconv.Atoi(logLevel)
	if err != nil {
		klog.ErrorS(err, "failed to parse log level")
		klogLevel = 2
	}
	config.klogLevel = klogLevel

	activeSettings := []interface{}{
		"httpPort", config.httpPort,
		"httpPortExternal", config.httpPortExternal,
		"tlsPort", config.tlsPort,
		"tlsPortExternal", config.tlsPortExternal,
		"mtlsPort", config.mtlsPort,
		"mtlsPortExternal", config.mtlsPortExternal,

		"serveMetrics", config.serveMetrics,
		"authType", config.authType,
		"useAuthService", config.useAuthService,
		"dockerInspectionTimeout", config.dockerImageInspectionTimeout,
		"cloudConfigPath", config.cloudConfig,
		"logLevel", logLevel,
	}

	if config.useAuthService {
		activeSettings = append(activeSettings,
			"authServiceName", config.authServiceName,
			"mtlsPortExternal", config.mtlsPortExternal,
			"mtlsPort", config.mtlsPort)
	}

	klog.InfoS("active settings", activeSettings...)

	config.credentials, config.credentialProvider, err = getCredentials()
	if err != nil {
		klog.ErrorS(err, "failed to get credentials for azure key vault")
		os.Exit(1)
	}

	err = validateCredentials(config.credentials)
	if err != nil {
		klog.ErrorS(err, "failed to get authorizer from azure key vault credentials")
		os.Exit(1)
	}

	config.kubeClient, err = newKubeClient()
	if err != nil {
		klog.ErrorS(err, "failed to build kube clientset", "master", params.masterURL, "kubeconfig", params.kubeconfig)
		os.Exit(1)
	}

	wg := new(sync.WaitGroup)
	wg.Add(2)

	authService, err := auth.NewAuthService(config.kubeClient, config.credentials)
	if err != nil {
		klog.ErrorS(err, "failed to create auth service")
		os.Exit(1)
	}
	config.authService = authService
	config.registry = registry.NewRegistry()

	createHTTPEndpoint(wg, config.httpPort, authService)
	createMTLSEndpoint(wg, config.mtlsPort, authService)
	createTLSEndpoint(wg, config.tlsPort, config.tlsCertFile, config.tlsKeyFile)

	wg.Wait()

}

func newKubeClient() (kubernetes.Interface, error) {
	cfg, err := kubernetesConfig.GetConfig() //clientcmd.BuildConfigFromFlags(params.masterURL, params.kubeconfig)
	if err != nil {
		klog.ErrorS(err, "failed to build kube config")
		os.Exit(1)
	}

	return kubernetes.NewForConfig(cfg)
}

func getCredentials() (credentialprovider.Credentials, credentialprovider.CredentialProvider, error) {
	if config.authType != "azureCloudConfig" {
		klog.V(4).InfoS("not using cloudConfig for auth - looking for azure key vault credentials in envrionment")
		cProvider, err := credentialprovider.NewFromEnvironment()
		if err != nil {
			return nil, cProvider, err
		}

		credentials, err := cProvider.GetAzureKeyVaultCredentials()
		return credentials, cProvider, err
	} else {
		klog.V(4).InfoS("using cloudConfig for auth - reading credentials", "file", config.cloudConfig)
		f, err := os.Open(config.cloudConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read azure config")
		}
		defer f.Close()

		cloudCnfProvider, err := credentialprovider.NewFromCloudConfig(f)
		if err != nil {
			return nil, cloudCnfProvider, fmt.Errorf("failed to create cloud config provider for azure key vault")
		}

		credentials, err := cloudCnfProvider.GetAzureKeyVaultCredentials()
		return credentials, cloudCnfProvider, err
	}
}

func validateCredentials(credentials credentialprovider.Credentials) error {
	klog.V(4).InfoS("checking credentials by getting authorizer from credentials")
	_, err := config.credentials.Authorizer()
	return err
}

func createHTTPEndpoint(wg *sync.WaitGroup, port string, authService *auth.AuthService) {
	router := mux.NewRouter()
	httpURL := fmt.Sprintf(":%s", port)

	if config.serveMetrics {
		router.Handle("/metrics", promhttp.Handler())
		klog.InfoS("serving metrics endpoint", "path", fmt.Sprintf("%s/metrics", httpURL))
	}

	router.HandleFunc("/auth/{namespace}/{pod}", authService.AuthValidateHandler)
	klog.InfoS("serving auth validation endpoint", "path", fmt.Sprintf("%s/auth/{namespace}/{pod}", httpURL))

	router.HandleFunc("/healthz", healthHandler)
	klog.InfoS("serving health endpoint", "path", fmt.Sprintf("%s/healthz", httpURL))

	go func() {
		err := http.ListenAndServe(httpURL, router)
		if err != nil {
			klog.ErrorS(err, "error serving metrics", "port", httpURL)
			os.Exit(1)
		}
		wg.Done()
	}()

}

func createTLSEndpoint(wg *sync.WaitGroup, port, tlsCertFile, tlsKeyFile string) {
	mutator := mutating.MutatorFunc(vaultSecretsMutator)
	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)
	internalLogger := &internalLog.Std{Debug: config.klogLevel >= 4}
	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, internalLogger)

	router := mux.NewRouter()
	tlsURL := fmt.Sprintf(":%s", port)

	router.Handle("/pods", podHandler)
	klog.InfoS("serving encrypted webhook endpoint", "path", fmt.Sprintf("%s/pods", tlsURL))

	router.HandleFunc("/healthz", healthHandler)
	klog.InfoS("serving encrypted healthz endpoint", "path", fmt.Sprintf("%s/healthz", tlsURL))

	go func() {
		server := createServer(router, tlsURL, nil)
		err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
		if err != nil {
			klog.ErrorS(err, "error serving endpoint", "port", tlsURL)
			os.Exit(1)
		}
		wg.Done()
	}()
}

func createMTLSEndpoint(wg *sync.WaitGroup, port string, authService *auth.AuthService) {
	if config.useAuthService {
		wg.Add(1)
		authURL := fmt.Sprintf(":%s", port)
		authRouter := mux.NewRouter()

		authRouter.HandleFunc("/auth/{namespace}/{pod}", authService.AuthHandler)
		authServer := authService.NewMTLSServer(authRouter, authURL)
		klog.InfoS("serving encrypted auth endpoint", "path", fmt.Sprintf("%s/auth", authURL))

		go func() {
			err := authServer.ListenAndServeTLS(config.tlsCertFile, config.tlsKeyFile)
			if err != nil {
				klog.ErrorS(err, "error serving auth", "port", authURL)
				os.Exit(1)
			}
			wg.Done()
		}()
	}
}

func createServer(router http.Handler, url string, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         url,
		TLSConfig:    tlsConfig,
		Handler:      router,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
}
