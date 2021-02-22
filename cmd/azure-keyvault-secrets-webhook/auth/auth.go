package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
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

type AuthService struct {
	kubeclient  kubernetes.Interface
	credentials credentialprovider.Credentials
	caCert      []byte
	caKey       []byte
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func NewAuthService(kubeclient kubernetes.Interface, credentials credentialprovider.Credentials) (*AuthService, error) {
	caCertDir := viper.GetString("ca_cert_dir")
	if caCertDir == "" {
		klog.InfoS("missing env var - must exist to use auth service", "env", "CA_CERT_DIR")
		return nil, fmt.Errorf("no ca cert directory found")
	}

	caCertFile := filepath.Join(caCertDir, "tls.crt")
	caKeyFile := filepath.Join(caCertDir, "tls.key")
	klog.V(4).InfoS("ca cert", "file", caCertFile)
	klog.V(4).InfoS("ca key", "file", caKeyFile)

	if !fileExists(caCertFile) {
		klog.InfoS("file does not exist", "file", caCertFile)
		return nil, fmt.Errorf("file does not exist")
	}

	if !fileExists(caKeyFile) {
		klog.InfoS("file does not exist", "file", caKeyFile)
		return nil, fmt.Errorf("file does not exist")
	}

	var err error
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		klog.ErrorS(err, "failed to read pem file for ca cert", "file", caCertFile)
		return nil, err
	}

	if len(caCert) == 0 {
		klog.InfoS("file is empty ", "file", caCertFile)
		return nil, fmt.Errorf("file %s is empty", caCertFile)
	}

	caKey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		klog.ErrorS(err, "failed to read pem file for ca key", "file", caKeyFile)
		return nil, err
	}

	if len(caKey) == 0 {
		klog.InfoS("file is empty ", "file", caKeyFile)
		return nil, fmt.Errorf("file %s is empty", caKeyFile)
	}

	klog.V(6).InfoS("ca cert", "pem", string(caCert))

	return &AuthService{
		kubeclient:  kubeclient,
		credentials: credentials,
		caCert:      caCert,
		caKey:       caKey,
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

	authValidationCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_auth_validations_total",
		Help: "The total number of successful auth validations",
	})

	authValidationFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "akv2k8s_auth_validations_failed_total",
		Help: "The total number of failed auth validations",
	})
)

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

		if err := json.NewEncoder(w).Encode(a.credentials); err != nil {
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
