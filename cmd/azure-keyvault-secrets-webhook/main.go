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
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	jsonlogs "k8s.io/component-base/logs/json"
	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

	cloudConfig                  string
	serveMetrics                 bool
	tlsCertFile                  string
	tlsKeyFile                   string
	caCert                       []byte
	caKey                        []byte
	authType                     string
	useAuthService               bool
	dockerImageInspectionTimeout int
	useAksCredentialsWithAcr     bool
	authServiceName              string
	kubeClient                   *kubernetes.Clientset
	versionEnvImage              string
	kubeconfig                   string
	masterURL                    string
	injectorDir                  string
	credentials                  credentialprovider.Credentials
	credentialProvider           credentialprovider.CredentialProvider
	klogLevel                    int
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

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return false, err
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return false, err
	}

	wh := podWebHook{
		clientset:                 clientset,
		namespace:                 req.Namespace,
		mutationID:                req.UID,
		injectorDir:               config.injectorDir,
		useAuthService:            config.useAuthService,
		authServiceName:           config.authServiceName,
		authServicePort:           config.mtlsPortExternal,
		authServiceValidationPort: config.httpPortExternal,
		caCert:                    config.caCert,
		caKey:                     config.caKey,
	}

	err = wh.mutatePodSpec(pod)
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

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		vars := mux.Vars(r)
		pod := podData{
			name:      vars["pod"],
			namespace: vars["namespace"],
		}

		if pod.name == "" || pod.namespace == "" {
			klog.InfoS("failed to parse url parameters", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		err := authorize(config.kubeClient, pod)

		if err != nil {
			klog.ErrorS(err, "failed to authorize request", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(config.credentials); err != nil {
			klog.ErrorS(err, "failed to json encode token", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			klog.InfoS("served oauth token", "pod", pod.name, "namespace", pod.namespace)
		}

	} else {
		klog.InfoS("invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

type validationPayload struct {
	ca string
}

type validationRes struct {
	caValid            bool
	awaitNewClientCert bool
}

func authValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		vars := mux.Vars(r)
		pod := podData{
			name:      vars["pod"],
			namespace: vars["namespace"],
		}

		if pod.name == "" || pod.namespace == "" {
			klog.InfoS("failed to parse url parameters", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		err := authorize(config.kubeClient, pod)
		if err != nil {
			klog.ErrorS(err, "failed to authorize request", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusForbidden)
			return
		}

		secretName := fmt.Sprintf("akv2k8s-%s", pod.name)
		secret, err := config.kubeClient.CoreV1().Secrets(pod.namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "failed to read secret", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		if string(secret.Data["ca.crt"]) == string(config.caCert) {
			w.WriteHeader(http.StatusOK)
		} else {
			runningPod, err := config.kubeClient.CoreV1().Pods(pod.namespace).Get(context.TODO(), pod.name, metav1.GetOptions{})
			if err != nil {
				klog.ErrorS(err, "failed to read pod", "pod", pod.name, "namespace", pod.namespace)
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			uid := types.UID(pod.name)
			newSecret, err := createAuthServicePodSecret(runningPod, pod.namespace, uid, config.caCert, config.caKey)
			if err != nil {
				klog.ErrorS(err, "failed to create secret", "pod", pod.name, "namespace", pod.namespace)
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			_, err = config.kubeClient.CoreV1().Secrets(pod.namespace).Update(context.TODO(), newSecret, metav1.UpdateOptions{})
			if err != nil {
				klog.ErrorS(err, "failed to update secret", "pod", pod.name, "namespace", pod.namespace)
				http.Error(w, "", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
		}
		// 200 OK      -> CA Cert is the current CA in use
		// 201 Created -> CA Cert has changed, a new client cert signed by the new CA will be availabe

		// w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		// if err := json.NewEncoder(w).Encode(result); err != nil {
		// 	klog.ErrorS(err, "failed to json encode token", "pod", pod.name, "namespace", pod.namespace)
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// } else {
		// 	klog.InfoS("served oauth token", "pod", pod.name, "namespace", pod.namespace)
		// }

	} else {
		klog.InfoS("invalid request method")
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
	viper.SetDefault("azurekeyvault_env_image", "spvest/azure-keyvault-env:latest")
	viper.SetDefault("docker_image_inspection_timeout", 20)
	viper.SetDefault("docker_image_inspection_use_acs_credentials", true)
	viper.SetDefault("auth_type", "cloudConfig")
	viper.SetDefault("use_auth_service", true)
	viper.SetDefault("metrics_enabled", false)
	viper.SetDefault("port_http", "80")
	viper.SetDefault("port", "443")
	viper.SetDefault("webhook_auth_service_port", "8443")
	viper.SetDefault("webhook_auth_service_port_internal", "8443")
	viper.SetDefault("env_injector_exec_dir", "/azure-keyvault/")
	viper.AutomaticEnv()
}

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	flag.StringVar(&params.version, "version", "", "Version of this component.")
	flag.StringVar(&params.versionEnvImage, "versionenvimage", "", "Version of the env image component.")
	flag.StringVar(&params.kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&params.masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
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
		tlsPort:                      viper.GetString("tls_port"),
		mtlsPortExternal:             viper.GetString("mtls_port_external"),
		mtlsPort:                     viper.GetString("mtls_port"),
		httpPort:                     viper.GetString("http_port"),
		authType:                     viper.GetString("auth_type"),
		serveMetrics:                 viper.GetBool("metrics_enabled"),
		tlsCertFile:                  fmt.Sprintf("%s/%s", viper.GetString("tls_cert_dir"), "tls.crt"),
		tlsKeyFile:                   fmt.Sprintf("%s/%s", viper.GetString("tls_cert_dir"), "tls.key"),
		useAuthService:               viper.GetBool("use_auth_service"),
		authServiceName:              viper.GetString("webhook_auth_service"),
		dockerImageInspectionTimeout: viper.GetInt("docker_image_inspection_timeout"),
		useAksCredentialsWithAcr:     viper.GetBool("docker_image_inspection_use_acs_credentials"),
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
		"tlsPort", config.tlsPort,
		"serveMetrics", config.serveMetrics,
		"authType", config.authType,
		"useAuthService", config.useAuthService,
		"useAksCredsWithAcr", config.useAksCredentialsWithAcr,
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

	getCertsForAuthService()
	getCredentials()
	getKubeClient()

	wg := new(sync.WaitGroup)
	wg.Add(2)

	createHTTPEndpoint(wg)
	createMTLSEndpoint(wg)
	createTLSEndpoint(wg)

	wg.Wait()

}

func getKubeClient() {
	cfg, err := clientcmd.BuildConfigFromFlags(params.masterURL, params.kubeconfig)
	if err != nil {
		klog.ErrorS(err, "failed to build kube config", "master", params.masterURL, "kubeconfig", params.kubeconfig)
		os.Exit(1)
	}

	config.kubeClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "failed to build kube clientset", "master", params.masterURL, "kubeconfig", params.kubeconfig)
		os.Exit(1)
	}
}

func getCertsForAuthService() {
	if config.useAuthService {
		caCertDir := viper.GetString("ca_cert_dir")
		if caCertDir == "" {
			klog.InfoS("missing env var - must exist to use auth service", "env", "CA_CERT_DIR")
			os.Exit(1)
		}

		caCertFile := filepath.Join(caCertDir, "tls.crt")
		caKeyFile := filepath.Join(caCertDir, "tls.key")

		var err error
		config.caCert, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			klog.ErrorS(err, "failed to read pem file for ca cert", "file", caCertFile)
			os.Exit(1)
		}

		config.caKey, err = ioutil.ReadFile(caKeyFile)
		if err != nil {
			klog.ErrorS(err, "failed to read pem file for ca key", "file", caKeyFile)
			os.Exit(1)
		}
	}
}

func getCredentials() {
	if config.authType != "cloudConfig" {
		klog.V(4).InfoS("not using cloudConfig for auth - looking for azure key vault credentials in envrionment")
		cProvider, err := credentialprovider.NewFromEnvironment()
		if err != nil {
			klog.ErrorS(err, "failed to create credentials provider from environment for azure key vault")
			os.Exit(1)
		}

		config.credentialProvider = cProvider
		config.credentials, err = cProvider.GetAzureKeyVaultCredentials()
		if err != nil {
			klog.ErrorS(err, "failed to get credentials for azure key vault")
			os.Exit(1)
		}

	} else {
		klog.V(4).InfoS("using cloudConfig for auth - reading credentials", "file", config.cloudConfig)
		f, err := os.Open(config.cloudConfig)
		if err != nil {
			klog.ErrorS(err, "failed to read azure config", "file", config.cloudConfig)
			os.Exit(1)
		}
		defer f.Close()

		cloudCnfProvider, err := credentialprovider.NewFromCloudConfig(f)
		if err != nil {
			klog.ErrorS(err, "failed to create cloud config provider for azure key vault", "file", config.cloudConfig)
			os.Exit(1)
		}

		config.credentialProvider = cloudCnfProvider
		config.credentials, err = cloudCnfProvider.GetAzureKeyVaultCredentials()
		if err != nil {
			klog.ErrorS(err, "failed to get azure key vault credentials", "file", config.cloudConfig)
			os.Exit(1)
		}
	}

	klog.V(4).InfoS("checking credentials by getting authorizer from credentials")
	_, err := config.credentials.Authorizer()
	if err != nil {
		klog.ErrorS(err, "failed to get authorizer from azure key vault credentials")
		os.Exit(1)
	}
}

func createTLSEndpoint(wg *sync.WaitGroup) {
	mutator := mutating.MutatorFunc(vaultSecretsMutator)
	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)
	internalLogger := &internalLog.Std{Debug: config.klogLevel >= 4}
	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, internalLogger)

	router := mux.NewRouter()
	tlsURL := fmt.Sprintf(":%s", config.tlsPort)

	router.Handle("/pods", podHandler)
	klog.InfoS("serving encrypted webhook endpoint", "path", fmt.Sprintf("%s/pods", tlsURL))

	router.HandleFunc("/healthz", healthHandler)
	klog.InfoS("serving encrypted healthz endpoint", "path", fmt.Sprintf("%s/healthz", tlsURL))

	go func() {
		server := createServer(router, tlsURL, nil)
		err := server.ListenAndServeTLS(config.tlsCertFile, config.tlsKeyFile)
		if err != nil {
			klog.ErrorS(err, "error serving endpoint", "port", tlsURL)
			os.Exit(1)
		}
		wg.Done()
	}()
}

func createHTTPEndpoint(wg *sync.WaitGroup) {
	httpMux := http.NewServeMux()
	httpURL := fmt.Sprintf(":%s", config.httpPort)

	if config.serveMetrics {
		httpMux.Handle("/metrics", promhttp.Handler())
		klog.InfoS("serving metrics endpoint", "path", fmt.Sprintf("%s/metrics", httpURL))
	}

	httpMux.HandleFunc("/auth/{namespace}/{pod}", authValidateHandler)
	httpMux.HandleFunc("/healthz", healthHandler)
	klog.InfoS("serving health endpoint", "path", fmt.Sprintf("%s/healthz", httpURL))

	go func() {
		err := http.ListenAndServe(httpURL, httpMux)
		if err != nil {
			klog.ErrorS(err, "error serving metrics", "port", httpURL)
			os.Exit(1)
		}
		wg.Done()
	}()

}

func createMTLSEndpoint(wg *sync.WaitGroup) {
	if config.useAuthService {
		wg.Add(1)
		authURL := fmt.Sprintf(":%s", config.mtlsPort)
		authRouter := mux.NewRouter()

		authRouter.HandleFunc("/auth/{namespace}/{pod}", authHandler)
		authServer := createServerWithMTLS(config.caCert, authRouter, authURL)
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

func createServerWithMTLS(caCert []byte, router http.Handler, url string) *http.Server {
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                clientCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	tlsConfig.BuildNameToCertificate()

	return createServer(router, url, tlsConfig)
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
