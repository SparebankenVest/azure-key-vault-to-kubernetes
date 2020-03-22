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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	envLookupKey = "@azurekeyvault"
)

type injectorConfig struct {
	namespace              string
	retryTimes             int
	waitTimeBetweenRetries int
	useAuthService         bool
	skipArgsValidation     bool
}

var config injectorConfig
var logger *log.Entry

type stop struct {
	error
}

func formatLogger() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})

	logger = log.WithFields(log.Fields{
		"component":   "akv2k8s",
		"application": "env-injector",
	})
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

type oauthToken struct {
	Token string `json:"token"`
}

func getCredentials(useAuthService bool) (vault.AzureKeyVaultCredentials, error) {
	if useAuthService {
		addr := viper.GetString("env_injector_auth_service")
		if addr == "" {
			logger.Fatal(fmt.Errorf("cannot call auth service: env var ENV_INJECTOR_AUTH_SERVICE does not exist"))
		}

		logger.Debug("loading client key pair")
		cert, err := tls.LoadX509KeyPair("/client-cert/clientCert", "/client-cert/clientKey")
		if err != nil {
			logger.Fatalf("failed to load client cert key pair, error: %+v", err)
		}

		logger.Debug("loading ca cert")
		caCert, err := ioutil.ReadFile("/client-cert/caCert")
		if err != nil {
			logger.Fatalf("failed to load ca cert to use with client certs, error: %+v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{cert},
				},
			},
			Timeout: time.Second * 10,
		}

		url := fmt.Sprintf("https://%s/auth?host=%s", addr, viper.GetString("HOSTNAME"))
		logger.Infof("requesting azure key vault oauth token from %s", url)

		res, err := client.Get(url)
		if err != nil {
			logger.Fatalf("request token failed from %s, error: %+v", url, err)
		}

		defer res.Body.Close()
		var creds vault.AzureKeyVaultOAuthCredentials
		err = json.NewDecoder(res.Body).Decode(&creds)

		if err != nil {
			return nil, fmt.Errorf("failed to decode body, error %+v", err)
		}

		return creds, nil
	}

	creds, err := vault.NewAzureKeyVaultCredentialsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials for azure key vault, error %+v", err)
	}
	return creds, nil
}

func verifyPKCS(signature string, plaintext string, pubkey rsa.PublicKey) bool {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hashed := sha256.Sum256([]byte(plaintext))
	err := rsa.VerifyPKCS1v15(&pubkey, crypto.SHA256, hashed[:], sig)
	return err == nil
}

func parseRsaPublicKey(pubPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing public signing key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, fmt.Errorf("Key type is not RSA")
}

func validateArgsSignature(origArgs string) {
	signatureB64 := viper.GetString("env_injector_args_signature")
	if signatureB64 == "" {
		logger.Fatalf("failed to get ENV_INJECTOR_ARGS_SIGNATURE")
	}

	signatureArray, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		logger.Fatalf("failed to decode base64 signature string, error: %+v", err)
	}

	signature := string(signatureArray)

	pubKeyBase64 := viper.GetString("env_injector_args_key")
	if pubKeyBase64 == "" {
		logger.Fatalf("failed to get ENV_INJECTOR_ARGS_KEY, error: %+v", err)
	}

	bPubKey, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		logger.Fatalf("failed to decode base64 public key string, error: %+v", err)
	}

	pubKey := string(bPubKey)

	pubRsaKey, err := parseRsaPublicKey(pubKey)
	if err != nil {
		logger.Fatalf("failed to parse rsa public key to verify args: %+v", err)
	}

	if !verifyPKCS(signature, origArgs, *pubRsaKey) {
		logger.Fatal("args does not match original args defined by env-injector")
	}
}

func initConfig() {
	viper.SetDefault("env_injector_retries", 3)
	viper.SetDefault("env_injector_wait_before_retry", 3)
	viper.SetDefault("env_injector_custom_auth", false)
	viper.SetDefault("env_injector_use_auth_service", true)
	viper.SetDefault("env_injector_skip_args_validation", false)
	viper.AutomaticEnv()
}

func setLogLevel(logLevel string) {
	if logLevel == "" {
		logLevel = log.InfoLevel.String()
	}

	logrusLevel, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("error setting log level: %s", err.Error())
	}
	log.SetLevel(logrusLevel)
}

func main() {
	initConfig()

	var origCommand string
	var origArgs []string

	logLevel := viper.GetString("LOG_LEVEL")
	setLogLevel(logLevel)
	formatLogger()

	logger.Debugf("azure key vault env injector initializing")

	config = injectorConfig{
		namespace:              viper.GetString("env_injector_pod_namespace"),
		retryTimes:             viper.GetInt("env_injector_retries"),
		waitTimeBetweenRetries: viper.GetInt("env_injector_wait_before_retry"),
		useAuthService:         viper.GetBool("env_injector_use_auth_service"),
		skipArgsValidation:     viper.GetBool("env_injector_skip_args_validation"),
	}

	if config.namespace == "" {
		logger.Fatalf("current namespace not provided in environment variable env_injector_pod_namespace")
	}

	logger = logger.WithFields(log.Fields{
		"namespace": config.namespace,
	})

	if config.useAuthService {
		logger.Info("using sentralized akv2k8s auth service for authentiction with azure key vault")
	} else {
		logger.Debug("akv2k8s auth service not enabled - will look for azure key vault credentials locally")
	}

	if len(os.Args) == 1 {
		logger.Fatal("no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly")
	} else {
		origCommand, err := exec.LookPath(os.Args[1])
		if err != nil {
			logger.Fatalf("binary not found: %+v", err)
		}

		origArgs = os.Args[1:]

		if !config.skipArgsValidation {
			validateArgsSignature(strings.Join(origArgs, " "))
		}

		logger.Infof("found original container command to be %s %s", origCommand, origArgs)
	}

	creds, err := getCredentials(config.useAuthService)
	if err != nil {
		log.Fatalf("failed to get credentials, error: %+v", err)
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
			keyVaultSecretSpec, err := azureKeyVaultSecretClient.AzurekeyvaultV1().AzureKeyVaultSecrets(config.namespace).Get(secretName, v1.GetOptions{})
			if err != nil {
				logger.Errorf("error getting azurekeyvaultsecret resource '%s', error: %s", secretName, err.Error())
				logger.Infof("will retry getting azurekeyvaultsecret resource up to %d times, waiting %d seconds between retries", config.retryTimes, config.waitTimeBetweenRetries)

				err = retry(config.retryTimes, time.Second*time.Duration(config.waitTimeBetweenRetries), func() error {
					keyVaultSecretSpec, err = azureKeyVaultSecretClient.AzurekeyvaultV1().AzureKeyVaultSecrets(config.namespace).Get(secretName, v1.GetOptions{})
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
