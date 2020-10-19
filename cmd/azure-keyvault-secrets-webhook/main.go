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
	"sync"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
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
	"k8s.io/client-go/tools/clientcmd"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	dockerHubHost           = "index.docker.io"
	oldDockerHubHost        = "docker.io"
	injectorDir             = "/azure-keyvault/"
	injectorExecutable      = "azure-keyvault-env"
	clientCertDir           = "/var/client-cert/"
	initContainerVolumeName = "azure-keyvault-env"
)

type azureKeyVaultConfig struct {
	port                         string
	cloudConfig                  string
	serveMetrics                 bool
	httpPort                     string
	tlsCertFile                  string
	tlsKeyFile                   string
	caCert                       []byte
	caKey                        []byte
	authType                     string
	useAuthService               bool
	dockerImageInspectionTimeout int
	useAksCredentialsWithAcs     bool
	authServiceName              string
	authServicePort              string
	authServicePortInternal      string
	kubeClient                   *kubernetes.Clientset
	credentials                  credentialprovider.Credentials
	version                      string
	versionEnvImage              string
	kubeconfig                   string
	masterURL                    string
}

type cmdParams struct {
	version         string
	versionEnvImage string
	kubeconfig      string
	masterURL       string
	cloudConfig     string
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

func vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	req := whcontext.GetAdmissionRequest(ctx)
	var pod *corev1.Pod

	switch v := obj.(type) {
	case *corev1.Pod:
		log.Infof("found pod to mutate in namespace '%s'", req.Namespace)
		pod = v
	default:
		return false, nil
	}

	podsInspectedCounter.Inc()

	err := mutatePodSpec(pod, req.Namespace, req.UID)
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

		if err := json.NewEncoder(w).Encode(config.credentials); err != nil {
			log.Errorf("failed to json encode token, error: %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			log.Infof("served oauth token to '%s/%s' at address '%s'", pod.namespace, pod.name, r.RemoteAddr)
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
	viper.SetDefault("log_level", "Info")
	viper.SetDefault("log_format", "fmt")
	viper.AutomaticEnv()
}

func init() {
	flag.StringVar(&params.version, "version", "", "Version of this component.")
	flag.StringVar(&params.versionEnvImage, "versionenvimage", "", "Version of the env image component.")
	flag.StringVar(&params.kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&params.masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&params.cloudConfig, "cloudconfig", "/etc/kubernetes/azure.json", "Path to cloud config. Only required if this is not at default location /etc/kubernetes/azure.json")
}

func main() {
	flag.Parse()
	initConfig()
	akv2k8s.Version = config.version

	logLevel := viper.GetString("log_level")
	setLogLevel(logLevel)

	logFormat := viper.GetString("log_format")
	setLogFormat(logFormat)

	akv2k8s.LogVersion()

	config = azureKeyVaultConfig{
		port:                         viper.GetString("port"),
		httpPort:                     viper.GetString("port_http"),
		authType:                     viper.GetString("auth_type"),
		serveMetrics:                 viper.GetBool("metrics_enabled"),
		tlsCertFile:                  fmt.Sprintf("%s/%s", viper.GetString("tls_cert_dir"), "tls.crt"),
		tlsKeyFile:                   fmt.Sprintf("%s/%s", viper.GetString("tls_cert_dir"), "tls.key"),
		useAuthService:               viper.GetBool("use_auth_service"),
		authServiceName:              viper.GetString("webhook_auth_service"),
		authServicePort:              viper.GetString("webhook_auth_service_port"),
		authServicePortInternal:      viper.GetString("webhook_auth_service_port_internal"),
		dockerImageInspectionTimeout: viper.GetInt("docker_image_inspection_timeout"),
		useAksCredentialsWithAcs:     viper.GetBool("docker_image_inspection_use_acs_credentials"),
		version:                      params.version,
		versionEnvImage:              params.versionEnvImage,
		cloudConfig:                  params.cloudConfig,
	}

	log.Info("Active settings:")
	log.Infof("  Webhook port              : %s", config.port)
	log.Infof("  Serve metrics             : %t", config.serveMetrics)
	log.Infof("  Auth type                 : %s", config.authType)
	log.Infof("  Use auth service          : %t", config.useAuthService)
	if config.useAuthService {
		log.Infof("  Auth service name         : %s", config.authServiceName)
		log.Infof("  Auth service port         : %s", config.authServicePort)
		log.Infof("  Auth service internal port: %s", config.authServicePortInternal)
	}
	log.Infof("  Use AKS creds with ACS    : %t", config.useAksCredentialsWithAcs)
	log.Infof("  Docker inspection timeout : %d", config.dockerImageInspectionTimeout)
	log.Infof("  Cloud config path         : %s", config.cloudConfig)

	mutator := mutating.MutatorFunc(vaultSecretsMutator)
	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)

	internalLogger := &internalLog.Std{Debug: logLevel == "debug" || logLevel == "trace"}
	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, internalLogger)

	var err error
	if config.useAuthService {
		log.Debug("loading ca to use for mtls and auth service")

		caCertDir := viper.GetString("ca_cert_dir")
		if caCertDir == "" {
			log.Fatalf("env var CA_CERT_DIR not provided - must exist to use auth service")
		}

		caCertFile := filepath.Join(caCertDir, "tls.crt")
		caKeyFile := filepath.Join(caCertDir, "tls.key")

		config.caCert, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			log.Fatalf("failed to read pem file for ca cert %s, error: %+v", caCertFile, err)
		}

		config.caKey, err = ioutil.ReadFile(caKeyFile)
		if err != nil {
			log.Fatalf("failed to read pem file for ca key %s, error: %+v", caKeyFile, err)
		}
	}

	if config.authType != "cloudConfig" {
		log.Debug("not using cloudConfig for auth - looking for azure key vault credentials in envrionment")
		cProvider, err := credentialprovider.NewFromEnvironment()
		if err != nil {
			log.Fatal(fmt.Errorf("failed to create credentials provider for azure key vault, error %+v", err))
		}

		config.credentials, err = cProvider.GetAzureKeyVaultCredentials()
		if err != nil {
			log.Fatal(fmt.Errorf("failed to get credentials for azure key vault, error %+v", err))
		}

	} else {
		log.Debugf("using cloudConfig for auth - reading credentials from %s", config.cloudConfig)
		f, err := os.Open(config.cloudConfig)
		if err != nil {
			log.Fatalf("Failed reading azure config from %s, error: %+v", config.cloudConfig, err)
		}
		defer f.Close()

		cloudCnfProvider, err := credentialprovider.NewFromCloudConfig(f)
		if err != nil {
			log.Fatalf("Failed reading azure config from %s, error: %+v", config.cloudConfig, err)
		}

		config.credentials, err = cloudCnfProvider.GetAzureKeyVaultCredentials()
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Debug("checking credentials by getting authorizer from credentials")
	_, err = config.credentials.Authorizer()
	if err != nil {
		log.Fatal("failed to get authorizer for azure key vault credentials")
	}

	log.Debug("getting azure key vault authorizer succeded")

	cfg, err := clientcmd.BuildConfigFromFlags(params.masterURL, params.kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// cfg, err := rest.InClusterConfig()
	// if err != nil {
	// 	log.Fatalf("failed to get kubernetes in cluster config, error: %+v", err)
	// }

	config.kubeClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	wg := new(sync.WaitGroup)
	wg.Add(2)

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
		wg.Done()
	}()

	router := mux.NewRouter()
	tlsURL := fmt.Sprintf(":%s", config.port)

	router.Handle("/pods", podHandler)
	log.Infof("Serving encrypted webhook at %s/pods", tlsURL)

	router.HandleFunc("/healthz", healthHandler)
	log.Infof("Serving encrypted healthz at %s/healthz", tlsURL)

	if config.useAuthService {
		wg.Add(1)
		authURL := fmt.Sprintf(":%s", config.authServicePortInternal)
		authRouter := mux.NewRouter()

		authRouter.HandleFunc("/auth/{namespace}/{pod}", authHandler)
		authServer := createServerWithMTLS(config.caCert, authRouter, authURL)

		go func() {
			err := authServer.ListenAndServeTLS(config.tlsCertFile, config.tlsKeyFile)
			if err != nil {
				log.Fatalf("error serving auth at %s: %+v", authURL, err)
			}
			wg.Done()
		}()
	}

	go func() {
		server := createServer(router, tlsURL, nil)
		log.Fatal(server.ListenAndServeTLS(config.tlsCertFile, config.tlsKeyFile))
		wg.Done()
	}()

	wg.Wait()
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
