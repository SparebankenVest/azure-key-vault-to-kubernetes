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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2alpha1"
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
	podName                string
	retryTimes             int
	waitTimeBetweenRetries int
	useAuthService         bool
	skipArgsValidation     bool
	authServiceAddress     string
	caCert                 string
	signatureB64           string
	pubKeyBase64           string
}

var config injectorConfig
var logger *log.Entry

type stop struct {
	error
}

func formatLogger(logFormat string) {
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

func initConfig() {
	viper.SetDefault("env_injector_retries", 3)
	viper.SetDefault("env_injector_wait_before_retry", 3)
	viper.SetDefault("env_injector_custom_auth", false)
	viper.SetDefault("env_injector_use_auth_service", true)
	viper.SetDefault("env_injector_skip_args_validation", false)
	viper.SetDefault("env_injector_log_level", "Info")
	viper.SetDefault("env_injector_log_format", "fmt")
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

func validateConfig(requiredEnvVars map[string]string) error {
	for key, value := range requiredEnvVars {
		if value == "" {
			return fmt.Errorf("environment variable %s not provided or empty", strings.ToUpper(key))
		}
	}
	return nil
}

func main() {
	initConfig()

	akv2k8s.Version = viper.GetString("version")

	var origCommand string
	var origArgs []string
	var err error

	logLevel := viper.GetString("env_injector_log_level")
	setLogLevel(logLevel)
	logFormat := viper.GetString("env_injector_log_format")
	formatLogger(logFormat)
	akv2k8s.LogVersion()

	logger.Debugf("azure key vault env injector initializing")

	config = injectorConfig{
		namespace:              viper.GetString("env_injector_pod_namespace"),
		podName:                viper.GetString("env_injector_pod_name"),
		retryTimes:             viper.GetInt("env_injector_retries"),
		waitTimeBetweenRetries: viper.GetInt("env_injector_wait_before_retry"),
		useAuthService:         viper.GetBool("env_injector_use_auth_service"),
		skipArgsValidation:     viper.GetBool("env_injector_skip_args_validation"),
		authServiceAddress:     viper.GetString("env_injector_auth_service"),
		caCert:                 viper.GetString("env_injector_ca_cert"),
		signatureB64:           viper.GetString("env_injector_args_signature"),
		pubKeyBase64:           viper.GetString("env_injector_args_key"),
	}

	requiredEnvVars := map[string]string{
		"env_injector_auth_service":   config.authServiceAddress,
		"env_injector_ca_cert":        config.caCert,
		"env_injector_args_signature": config.signatureB64,
		"env_injector_args_key":       config.pubKeyBase64,
	}

	err = validateConfig(requiredEnvVars)
	if err != nil {
		logger.Fatalf("failed validating config, error: %+v", err)
	}

	logger = logger.WithFields(log.Fields{
		"namespace": config.namespace,
	})

	if config.useAuthService {
		logger.Info("using centralized akv2k8s auth service for authentiction with azure key vault")
	} else {
		logger.Debug("akv2k8s auth service not enabled - will look for azure key vault credentials locally")
	}

	if len(os.Args) == 1 {
		logger.Fatal("no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly")
	} else {
		origCommand, err = exec.LookPath(os.Args[1])
		if err != nil {
			logger.Fatalf("binary not found: %+v", err)
		}

		origArgs = os.Args[1:]

		if !config.skipArgsValidation {
			validateArgsSignature(strings.Join(origArgs, " "), config.signatureB64, config.pubKeyBase64)
		}

		logger.Infof("found original container command to be %s %s", origCommand, origArgs)
	}

	creds, err := getCredentials(config.useAuthService, config.authServiceAddress, config.caCert)
	if err != nil {
		log.Warnf("failed to get credentials, will retry %d times", config.retryTimes)
		err = retry(config.retryTimes, time.Second*time.Duration(config.waitTimeBetweenRetries), func() error {
			creds, err = getCredentials(config.useAuthService, config.authServiceAddress, config.caCert)
			if err != nil {
				logger.Warnf("failed to get credentials, error: %+v", err)
				return err
			}
			logger.Info("succeded getting credentials")
			return nil
		})
		if err != nil {
			logger.Fatalf("failed to get credentials %d times, error: %+v", config.retryTimes, err)
		}
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
			keyVaultSecretSpec, err := azureKeyVaultSecretClient.KeyvaultV2alpha1().AzureKeyVaultSecrets(config.namespace).Get(secretName, v1.GetOptions{})
			if err != nil {
				logger.Warnf("failed to get azurekeyvaultsecret resource '%s', error: %s", secretName, err.Error())
				logger.Infof("will retry getting azurekeyvaultsecret resource up to %d times, waiting %d seconds between retries", config.retryTimes, config.waitTimeBetweenRetries)

				err = retry(config.retryTimes, time.Second*time.Duration(config.waitTimeBetweenRetries), func() error {
					keyVaultSecretSpec, err = azureKeyVaultSecretClient.KeyvaultV2alpha1().AzureKeyVaultSecrets(config.namespace).Get(secretName, v1.GetOptions{})
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
				logger.Infof("secret %s injected into env var %s for executable %s", keyVaultSecretSpec.Spec.Vault.Object.Name, name, origCommand)
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
