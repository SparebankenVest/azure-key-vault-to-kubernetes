// Copyright © 2019 Sparebanken Vest
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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	envLookupKey = "@azurekeyvault"
)

var logger *log.Entry

type stop struct {
	error
}

func formatLogger() {
	var logLevel string
	var ok bool

	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})

	logger = log.WithFields(log.Fields{
		"component":   "akv2k8s",
		"application": "env-injector",
	})

	if logLevel, ok = os.LookupEnv("ENV_INJECTOR_LOG_LEVEL"); !ok {
		logLevel = log.InfoLevel.String()
	}

	logrusLevel, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("error setting log level: %s", err.Error())
	}
	log.SetLevel(logrusLevel)
}

// Retry will wait for a duration, retry n times, return if succeed or fails
// Thanks to Nick Stogner: https://upgear.io/blog/simple-golang-retry-function/
func retry(attempts int, sleep time.Duration, fn func() error) error {
	if err := fn(); err != nil {
		if s, ok := err.(stop); ok {
			// Return the original error for later checking
			return s.error
		}

		if attempts--; attempts > 0 {
			time.Sleep(sleep)
			return retry(attempts, 2*sleep, fn)
		}
		return err
	}
	return nil
}

func getSecretFromKeyVault(azureKeyVaultSecret *akv.AzureKeyVaultSecret, query string, vaultService vault.Service) (string, error) {
	var secretHandler EnvSecretHandler

	switch azureKeyVaultSecret.Spec.Vault.Object.Type {
	case akv.AzureKeyVaultObjectTypeSecret:
		transformator, err := transformers.CreateTransformator(&azureKeyVaultSecret.Spec.Output)
		if err != nil {
			return "", err
		}
		secretHandler = NewAzureKeyVaultSecretHandler(azureKeyVaultSecret, query, *transformator, vaultService)
	case akv.AzureKeyVaultObjectTypeCertificate:
		secretHandler = NewAzureKeyVaultCertificateHandler(azureKeyVaultSecret, query, vaultService)
	case akv.AzureKeyVaultObjectTypeKey:
		secretHandler = NewAzureKeyVaultKeyHandler(azureKeyVaultSecret, query, vaultService)
	case akv.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		secretHandler = NewAzureKeyVaultMultiKeySecretHandler(azureKeyVaultSecret, query, vaultService)
	default:
		return "", fmt.Errorf("azure key vault object type '%s' not currently supported", azureKeyVaultSecret.Spec.Vault.Object.Type)
	}
	return secretHandler.Handle()
}

func getCredentials(hasClientCert bool, customAuth bool) (*vault.AzureKeyVaultCredentials, error) {
	if hasClientCert {
		addr, ok := os.LookupEnv("ENV_INJECTOR_AUTH_SERVICE")
		if !ok {
			log.Fatal(fmt.Errorf("cannot call auth service: env var ENV_INJECTOR_AUTH_SERVICE does not exist"))
		}

		// Get token from Auth endpoint
		cert, err := tls.LoadX509KeyPair("/client-cert/clientCert", "/client-cert/clientKey")
		if err != nil {
			log.Fatal(err)
		}

		// Create a CA certificate pool and add cert.pem to it
		caCert, err := ioutil.ReadFile("/client-cert/caCert")
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Create a HTTPS client and supply the created CA pool and certificate
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{cert},
				},
			},
		}

		r, err := client.Get(fmt.Sprintf("https://%s/auth", addr))
		if err != nil {
			log.Fatal(err)
		}

		// Read the response body
		defer r.Body.Close()
		token, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}

		creds, err := vault.NewAzureKeyVaultCredentialsFromOauthToken(string(token))
		if err != nil {
			return nil, fmt.Errorf("failed to get credentials for azure key vault, error %+v", err)
		}
		return creds, nil
	}

	if customAuth {
		logger.Debug("getting credentials for azure key vault using azure credentials supplied to pod")

		creds, err := vault.NewAzureKeyVaultCredentialsFromEnvironment()
		if err != nil {
			return nil, fmt.Errorf("failed to get credentials for azure key vault, error %+v", err)
		}
		return creds, nil
	}

	return nil, fmt.Errorf("unable to authenticate: neither client cert or custom auth exists")
}

func main() {
	var origCommand string
	var origArgs []string

	formatLogger()

	logger.Debugf("azure key vault env injector initializing")
	namespace := os.Getenv("ENV_INJECTOR_POD_NAMESPACE")
	if namespace == "" {
		logger.Fatalf("current namespace not provided in environment variable env_injector_pod_namespace")
	}

	logger = logger.WithFields(log.Fields{
		"namespace": namespace,
	})

	var err error
	retryTimes := 3
	waitTimeBetweenRetries := 3

	retryTimesEnv, ok := os.LookupEnv("ENV_INJECTOR_RETRIES")
	if ok {
		if retryTimes, err = strconv.Atoi(retryTimesEnv); err != nil {
			logger.Errorf("failed to convert ENV_INJECTOR_RETRIES env var into int, value was '%s', using default value of %d", retryTimesEnv, retryTimes)
		}
	}

	waitTimeBetweenRetriesEnv, ok := os.LookupEnv("ENV_INJECTOR_WAIT_BEFORE_RETRY")
	if ok {
		if waitTimeBetweenRetries, err := strconv.Atoi(retryTimesEnv); err != nil {
			logger.Errorf("failed to convert ENV_INJECTOR_WAIT_BEFORE_RETRY env var into int, value was '%s', using default value of %d", waitTimeBetweenRetriesEnv, waitTimeBetweenRetries)
		}
	}

	customAuth, err := strconv.ParseBool(os.Getenv("ENV_INJECTOR_CUSTOM_AUTH"))
	if err != nil {
		log.Fatal("failed to parse env var ENV_INJECTOR_CUSTOM_AUTH as bool, error: %+v", err)
	}
	logger.Debugf("use custom auth: %s", customAuth)

	logger = logger.WithFields(log.Fields{
		"custom_auth": customAuth,
	})

	hasClientCert, err := strconv.ParseBool(os.Getenv("ENV_INJECTOR_HAS_CLIENT_CERT"))

	if len(os.Args) == 1 {
		logger.Fatal("no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly")
	} else {
		origCommand, err = exec.LookPath(os.Args[1])
		if err != nil {
			logger.Fatalf("binary not found: %+v", err)
		}

		origArgs = os.Args[1:]

		logger.Infof("found original container command to be %s %s", origCommand, origArgs)
	}

	creds, err := getCredentials(hasClientCert, customAuth)
	if err != nil {
		log.Fatal("failed to get credentials, error: %+v", err)
	}

	vaultService := vault.NewService(creds)

	logger.Debug("reading azurekeyvaultsecret's referenced in env variables")
	cfg, err := rest.InClusterConfig()
	if err != nil {
		logger.Fatalf("error building kubeconfig: %s", err.Error())
	}

	azureKeyVaultSecretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		logger.Fatalf("error building azurekeyvaultsecret clientset: %+v", err)
	}

	environ := os.Environ()

	for i, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]

		// e.g. my-akv-secret-name@azurekeyvault?some-sub-key
		if strings.Contains(value, envLookupKey) {
			// e.g. my-akv-secret-name?some-sub-key
			logger.Debugf("found env var '%s' to get azure key vault secret for", name)
			secretName := strings.Join(strings.Split(value, envLookupKey), "")

			if secretName == "" {
				logger.Fatalf("error extracting secret name from env variable '%s' with lookup value '%s' - not properly formatted", name, value)
			}

			var secretQuery string
			if query := strings.Split(secretName, "?"); len(query) > 1 {
				if len(query) > 2 {
					logger.Fatalf("error extracting secret query from '%s' - has multiple query elements defined with '?' - only one supported", secretName)
				}
				secretName = query[0]
				secretQuery = query[1]
				logger.Debugf("found query in env var '%s', '%s'", value, secretQuery)
			}

			logger.Debugf("getting azurekeyvaultsecret resource '%s' from kubernetes", secretName)
			keyVaultSecretSpec, err := azureKeyVaultSecretClient.AzurekeyvaultV1alpha1().AzureKeyVaultSecrets(namespace).Get(secretName, v1.GetOptions{})
			if err != nil {
				logger.Errorf("error getting azurekeyvaultsecret resource '%s', error: %s", secretName, err.Error())
				logger.Infof("will retry getting azurekeyvaultsecret resource up to %d times, waiting %d seconds between retries", retryTimes, waitTimeBetweenRetries)

				err = retry(retryTimes, time.Second*time.Duration(waitTimeBetweenRetries), func() error {
					keyVaultSecretSpec, err = azureKeyVaultSecretClient.AzurekeyvaultV1alpha1().AzureKeyVaultSecrets(namespace).Get(secretName, v1.GetOptions{})
					if err != nil {
						logger.Errorf("error getting azurekeyvaultsecret resource '%s', error: %+v", secretName, err)
						return err
					}
					logger.Infof("succeded getting azurekeyvaultsecret resource '%s'", secretName)
					return nil
				})
				if err != nil {
					logger.Fatalf("error getting azurekeyvaultsecret resource '%s', error: %s", secretName, err.Error())
				}
			}

			logger.Debugf("getting secret value for '%s' from azure key vault, to inject into env var %s", keyVaultSecretSpec.Spec.Vault.Object.Name, name)
			secret, err := getSecretFromKeyVault(keyVaultSecretSpec, secretQuery, vaultService)
			if err != nil {
				logger.Fatalf("failed to read secret '%s', error %+v", keyVaultSecretSpec.Spec.Vault.Object.Name, err)
			}

			if secret == "" {
				logger.Fatalf("secret not found in azure key vault: %s", keyVaultSecretSpec.Spec.Vault.Object.Name)
			} else {
				logger.Infof("secret %s injected into evn var %s for executable %s", keyVaultSecretSpec.Spec.Vault.Object.Name, name, origCommand)
				environ[i] = fmt.Sprintf("%s=%s", name, secret)
			}
		}
	}

	logger.Infof("starting process %s %v with secrets in env vars", origCommand, origArgs)
	err = syscall.Exec(origCommand, origArgs, environ)
	if err != nil {
		logger.Fatalf("failed to exec process '%s': %s", origCommand, err.Error())
	}

	logger.Info("azure key vault env injector successfully injected env variables with secrets")
}
