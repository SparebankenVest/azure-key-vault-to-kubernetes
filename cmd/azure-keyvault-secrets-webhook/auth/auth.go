package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// AzureCloudEnv defines the different Azure cloud environments
type AzureCloudEnv string

const (
	AzurePublicCloud       AzureCloudEnv = "AzurePublicCloud"
	AzureUSGovernmentCloud AzureCloudEnv = "AzureUSGovernment"
	// Add other environments if needed, e.g., AzureChinaCloud, AzureGermanyCloud
)

// keyVaultScopes maps AzureCloudEnv to its corresponding Key Vault default scope
var keyVaultScopes = map[AzureCloudEnv]string{
	AzurePublicCloud:       "https://vault.azure.net/.default",
	AzureUSGovernmentCloud: "https://vault.usgovcloudapi.net/.default",
	// Add other environments as they are needed
}

type AuthService struct {
	kubeclient    kubernetes.Interface
	credentials   azure.LegacyTokenCredential
	caCert        []byte
	caKey         []byte
	keyVaultScope string // Added field for configurable Key Vault scope
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// NewAuthService creates a new authentication service for akv2k8s
func NewAuthService(kubeclient kubernetes.Interface, credentials azure.LegacyTokenCredential) (*AuthService, error) {
	caCertDir := viper.GetString("ca_cert_dir")
	if caCertDir == "" {
		klog.InfoS("missing env var - must exist to use auth service", "env", "CA_CERT_DIR")
		return nil, fmt.Errorf("no ca cert directory found")
	}

	caCertFile := filepath.Join(caCertDir, "tls.crt")
	caKeyFile := filepath.Join(caCertDir, "tls.key")
	klog.V(4).InfoS("auth service ca cert", "file", caCertFile)
	klog.V(4).InfoS("auth service ca key", "file", caKeyFile)

	if !fileExists(caCertFile) {
		klog.InfoS("file does not exist", "file", caCertFile)
		return nil, fmt.Errorf("file does not exist")
	}

	if !fileExists(caKeyFile) {
		klog.InfoS("file does not exist", "file", caKeyFile)
		return nil, fmt.Errorf("file does not exist")
	}

	var err error
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		klog.ErrorS(err, "failed to read pem file for ca cert", "file", caCertFile)
		return nil, err
	}

	if len(caCert) == 0 {
		klog.InfoS("file is empty ", "file", caCertFile)
		return nil, fmt.Errorf("file %s is empty", caCertFile)
	}

	caKey, err := os.ReadFile(caKeyFile)
	if err != nil {
		klog.ErrorS(err, "failed to read pem file for ca key", "file", caKeyFile)
		return nil, err
	}

	if len(caKey) == 0 {
		klog.InfoS("file is empty ", "file", caKeyFile)
		return nil, fmt.Errorf("file %s is empty", caKeyFile)
	}

	// Determine the Azure environment from environment variable
	azureEnvStr := os.Getenv("AZURE_ENVIRONMENT")
	if azureEnvStr == "" {
		azureEnvStr = string(AzurePublicCloud) // Default to Azure Public Cloud if not set
	}

	azureEnv := AzureCloudEnv(azureEnvStr)
	keyVaultScope, found := keyVaultScopes[azureEnv]
	if !found {
		klog.InfoS("unsupported AZURE_ENVIRONMENT specified, defaulting to Azure Public Cloud Key Vault scope", "environment", azureEnvStr)
		keyVaultScope = keyVaultScopes[AzurePublicCloud]
	}
	klog.InfoS("using Azure Key Vault scope", "environment", azureEnvStr, "scope", keyVaultScope)

	return &AuthService{
		kubeclient:    kubeclient,
		credentials:   credentials,
		caCert:        caCert,
		caKey:         caKey,
		keyVaultScope: keyVaultScope, // Initialize the new field
	}, nil
}

var (
	authRequestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_auth_requests_total",
		Help: "The total number of successful auth requests",
	})

	authRequestsFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_auth_requests_failed_total",
		Help: "The total number failed auth requests",
	})
)

// AuthHandler handles authentiction requests to the Auth Service
func (a AuthService) AuthHandler(w http.ResponseWriter, r *http.Request) {
	authRequestsCounter.Inc()

	if r.Method == "GET" {
		vars := mux.Vars(r)
		pod := podData{
			name:      vars["pod"],
			namespace: vars["namespace"],
		}

		if pod.name == "" || pod.namespace == "" {
			klog.InfoS("failed to parse url parameters", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			authRequestsFailures.Inc()
			return
		}

		err := authorize(a.kubeclient, pod)

		if err != nil {
			klog.ErrorS(err, "failed to authorize request", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusForbidden)
			authRequestsFailures.Inc()
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		token, err := a.credentials.GetToken(context.TODO(), policy.TokenRequestOptions{Scopes: []string{a.keyVaultScope}})
		if err != nil {
			klog.ErrorS(err, "failed to get token", "pod", pod.name, "namespace", pod.namespace)
			// Ensure an error response is sent to the client
			http.Error(w, "Failed to get Azure token", http.StatusInternalServerError)
			return // Added return to prevent further execution after error
		}
		if err := json.NewEncoder(w).Encode(map[string]string{"oauth_token": token.Token}); err != nil {
			klog.ErrorS(err, "failed to json encode token", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			klog.InfoS("served oauth token", "pod", pod.name, "namespace", pod.namespace)
		}
	} else {
		authRequestsFailures.Inc()
		klog.InfoS("invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// AuthValidateHandler validates if a pod has valid credentials for authenticating with the Auth Service.
// If not it will issue a new Secret for the pod to use when authenticating.
func (a AuthService) AuthValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		vars := mux.Vars(r)
		qParams := r.URL.Query()

		pod := podData{
			name:       vars["pod"],
			namespace:  vars["namespace"],
			authSecret: qParams.Get("secret"),
		}

		if pod.name == "" || pod.namespace == "" {
			klog.InfoS("failed to parse url parameters", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		if pod.authSecret == "" {
			klog.InfoS("failed to parse query parameters", "secret", pod.authSecret, "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		err := authorize(a.kubeclient, pod)
		if err != nil {
			klog.ErrorS(err, "failed to authorize request", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusForbidden)
			return
		}

		runningPod, err := a.kubeclient.CoreV1().Pods(pod.namespace).Get(context.TODO(), pod.name, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "failed to read pod", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		uid := types.UID(pod.name)
		newSecret, err := a.NewPodSecret(runningPod, pod.namespace, uid)
		if err != nil {
			klog.ErrorS(err, "failed to create secret", "pod", pod.name, "namespace", pod.namespace)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		// set secret name explicit, and not use generated name
		newSecret.Name = pod.authSecret

		notFound := false
		secret, err := a.kubeclient.CoreV1().Secrets(pod.namespace).Get(context.TODO(), pod.authSecret, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				notFound = true
				klog.InfoS("secret not found", "secret", pod.authSecret, "namespace", pod.namespace)
			} else {
				klog.ErrorS(err, "failed to read secret", "secret", pod.authSecret, "namespace", pod.namespace)
				http.Error(w, "", http.StatusBadRequest)
				return
			}
		}

		if notFound {
			_, err = a.kubeclient.CoreV1().Secrets(pod.namespace).Create(context.TODO(), newSecret, metav1.CreateOptions{})
			if err != nil {
				klog.ErrorS(err, "failed to create secret", "pod", pod.name, "namespace", pod.namespace)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		} else if string(secret.Data["ca.crt"]) == string(a.caCert) {
			w.WriteHeader(http.StatusOK)
		} else {
			_, err = a.kubeclient.CoreV1().Secrets(pod.namespace).Update(context.TODO(), newSecret, metav1.UpdateOptions{})
			if err != nil {
				klog.ErrorS(err, "failed to update secret", "pod", pod.name, "namespace", pod.namespace)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		}
	} else {
		klog.InfoS("invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// NewPodSecret creates a new Kubernetes Secret with a client certificate needed for authenticating with the AuthService
func (a AuthService) NewPodSecret(pod *corev1.Pod, namespace string, mutationID types.UID) (*corev1.Secret, error) {
	// Create secret containing CA cert and mTLS credentials

	clientCert, err := generateClientCert(mutationID, 24, a.caCert, a.caKey)
	if err != nil {
		return nil, err
	}

	value := map[string][]byte{
		"ca.crt":  clientCert.CA,
		"tls.crt": clientCert.Crt,
		"tls.key": clientCert.Key,
	}

	name := pod.GetName()
	ownerReferences := pod.GetOwnerReferences()
	if name == "" {
		if len(ownerReferences) > 0 {
			if strings.Contains(ownerReferences[0].Name, "-") {
				generateNameSlice := strings.Split(ownerReferences[0].Name, "-")
				name = strings.Join(generateNameSlice[:len(generateNameSlice)-1], "-")
			} else {
				name = ownerReferences[0].Name
			}
		} else {
			name = pod.GetGenerateName()
		}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("akv2k8s-%s", name),
			Namespace:       namespace,
			OwnerReferences: ownerReferences,
		},
		Type: corev1.SecretTypeTLS,
		Data: value,
	}

	return secret, nil
}

// NewMTLSServer creates a new http server with mtls authentication enabled
func (a AuthService) NewMTLSServer(router http.Handler, url string) *http.Server {
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(a.caCert)

	tlsConfig := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                clientCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	tlsConfig.BuildNameToCertificate()

	return &http.Server{
		Addr:         url,
		TLSConfig:    tlsConfig,
		Handler:      router,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
}
