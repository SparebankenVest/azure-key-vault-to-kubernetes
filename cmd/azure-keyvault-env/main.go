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
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/keyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	"github.com/spf13/viper"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	envLookupKey = "@azurekeyvault"
)

type injectorConfig struct {
	namespace              string
	podName                string
	clientCertDir          string
	retryTimes             int
	waitTimeBetweenRetries int
	useAuthService         bool
	skipArgsValidation     bool
	authServiceAddress     string
	signatureB64           string
	pubKeyBase64           string
}

var config injectorConfig

type stop struct {
	error
}

// func formatLogger(logFormat string) {
// 	switch logFormat {
// 	case "fmt":
// 		log.SetFormatter(&log.TextFormatter{
// 			DisableColors: true,
// 			FullTimestamp: true,
// 		})
// 	case "json":
// 		log.SetFormatter(&log.JSONFormatter{})
// 	default:
// 		log.Warnf("Log format %s not supported - using default fmt", logFormat)
// 	}

// 	logger = log.WithFields(log.Fields{
// 		"component":   "akv2k8s",
// 		"application": "env-injector",
// 	})
// }

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

// func setLogLevel(logLevel string) {
// 	if logLevel == "" {
// 		logLevel = log.InfoLevel.String()
// 	}

// 	logrusLevel, err := log.ParseLevel(logLevel)
// 	if err != nil {
// 		log.Errorf("error setting log level: %s", err.Error())
// 	}
// 	log.SetLevel(logrusLevel)
// }

func validateConfig(requiredEnvVars map[string]string) error {
	for key, value := range requiredEnvVars {
		if value == "" {
			return fmt.Errorf("environment variable %s not provided or empty", strings.ToUpper(key))
		}
	}
	return nil
}

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	initConfig()

	akv2k8s.Version = viper.GetString("version")

	var origCommand string
	var origArgs []string
	var err error

	// logLevel := viper.GetString("env_injector_log_level")
	// setLogLevel(logLevel)
	// logFormat := viper.GetString("env_injector_log_format")
	// formatLogger(logFormat)
	akv2k8s.LogVersion()

	klog.InfoS("azure key vault env injector initializing")

	config = injectorConfig{
		namespace:              viper.GetString("env_injector_pod_namespace"),
		podName:                viper.GetString("env_injector_pod_name"),
		clientCertDir:          viper.GetString("env_injector_client_cert_dir"),
		retryTimes:             viper.GetInt("env_injector_retries"),
		waitTimeBetweenRetries: viper.GetInt("env_injector_wait_before_retry"),
		useAuthService:         viper.GetBool("env_injector_use_auth_service"),
		skipArgsValidation:     viper.GetBool("env_injector_skip_args_validation"),
		authServiceAddress:     viper.GetString("env_injector_auth_service"),
		signatureB64:           viper.GetString("env_injector_args_signature"),
		pubKeyBase64:           viper.GetString("env_injector_args_key"),
	}

	requiredEnvVars := map[string]string{
		"env_injector_auth_service":   config.authServiceAddress,
		"env_injector_args_signature": config.signatureB64,
		"env_injector_args_key":       config.pubKeyBase64,
	}

	err = validateConfig(requiredEnvVars)
	if err != nil {
		klog.ErrorS(err, "failed validating config")
		os.Exit(1)
	}

	if config.useAuthService {
		klog.V(4).InfoS("using centralized akv2k8s auth service for authentication with azure key vault")
	} else {
		klog.V(2).InfoS("akv2k8s auth service not enabled - will look for azure key vault credentials locally")
	}

	if len(os.Args) == 1 {
		klog.ErrorS(err, "no command is given")
		os.Exit(1)
	} else {
		origCommand, err = exec.LookPath(os.Args[1])
		if err != nil {
			klog.ErrorS(err, "binary not found")
		}

		origArgs = os.Args[1:]

		if !config.skipArgsValidation {
			validateArgsSignature(strings.Join(origArgs, " "), config.signatureB64, config.pubKeyBase64)
		}

		klog.InfoS("found original container command", "cmd", origCommand, "args", origArgs)
	}

	creds, err := getCredentials(config.useAuthService, config.authServiceAddress, config.clientCertDir)
	if err != nil {
		klog.V(4).InfoS("failed to get credentials, will retry", "retryTimes", config.retryTimes)
		err = retry(config.retryTimes, time.Second*time.Duration(config.waitTimeBetweenRetries), func() error {
			creds, err = getCredentials(config.useAuthService, config.authServiceAddress, config.clientCertDir)
			if err != nil {
				return err
			}
			klog.Info("succeded getting credentials")
			return nil
		})
		if err != nil {
			klog.ErrorS(err, "failed to get credentials", "failedTimes", config.retryTimes)
			os.Exit(1)
		}
	}

	vaultService := vault.NewService(creds)

	klog.V(4).InfoS("reading azurekeyvaultsecret's referenced in env variables")
	cfg, err := rest.InClusterConfig()
	if err != nil {
		klog.ErrorS(err, "error building kubeconfig")
		os.Exit(1)
	}

	azureKeyVaultSecretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "error building azurekeyvaultsecret clientset")
		os.Exit(1)
	}

	environ := os.Environ()

	for i, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]

		// e.g. my-akv-secret-name@azurekeyvault?some-sub-key
		if strings.Contains(value, envLookupKey) {
			// e.g. my-akv-secret-name?some-sub-key
			klog.V(4).InfoS("found env var to get azure key vault secret for", "env", name)
			akvsName := strings.Join(strings.Split(value, envLookupKey), "")

			if akvsName == "" {
				klog.ErrorS(fmt.Errorf("error extracting secret name"), "env variable not properly formatted", "env", name, "value", value)
				os.Exit(1)
			}

			var secretQuery string
			if query := strings.Split(akvsName, "?"); len(query) > 1 {
				if len(query) > 2 {
					klog.ErrorS(fmt.Errorf("error extracting secret query"), "multiple query elements defined with '?' - only one supported", "secret", akvsName)
					os.Exit(1)
				}
				akvsName = query[0]
				secretQuery = query[1]
				klog.V(4).InfoS("found query in env var", "env", name, "value", value, "query", secretQuery)
			}

			klog.V(4).InfoS("getting azurekeyvaultsecret", "azurekeyvaultsecret", klog.KRef(config.namespace, akvsName))
			akvs, err := azureKeyVaultSecretClient.KeyvaultV2beta1().AzureKeyVaultSecrets(config.namespace).Get(context.TODO(), akvsName, v1.GetOptions{})
			if err != nil {
				klog.ErrorS(err, "failed to get azurekeyvaultsecret", "azurekeyvaultsecret", klog.KRef(config.namespace, akvsName))
				klog.InfoS("will retry getting azurekeyvaultsecret", "azurekeyvaultsecret", klog.KRef(config.namespace, akvsName), "retryTimes", config.retryTimes, "delay", config.waitTimeBetweenRetries)

				err = retry(config.retryTimes, time.Second*time.Duration(config.waitTimeBetweenRetries), func() error {
					akvs, err = azureKeyVaultSecretClient.KeyvaultV2beta1().AzureKeyVaultSecrets(config.namespace).Get(context.TODO(), akvsName, v1.GetOptions{})
					if err != nil {
						klog.V(4).ErrorS(err, "error getting azurekeyvaultsecret", "azurekeyvaultsecret", klog.KRef(config.namespace, akvsName))
						return err
					}
					klog.InfoS("succeded getting azurekeyvaultsecret", "azurekeyvaultsecret", klog.KObj(akvs))
					return nil
				})
				if err != nil {
					klog.ErrorS(err, "error getting azurekeyvaultsecret", "azurekeyvaultsecret", klog.KRef(config.namespace, akvsName))
					os.Exit(1)
				}
			}

			klog.V(4).InfoS("getting secret value for from azure key vault, to inject into env var", "azurekeyvaultsecret", klog.KObj(akvs), "env", name)
			secret, err := getSecretFromKeyVault(akvs, secretQuery, vaultService)
			if err != nil {
				klog.ErrorS(err, "failed to read secret from azure key vault", "azurekeyvaultsecret", klog.KObj(akvs))
				os.Exit(1)
			}

			if secret == "" {
				klog.ErrorS(fmt.Errorf("secret value empty"), "secret not found in azure key vault", "azurekeyvaultsecret", klog.KObj(akvs))
				os.Exit(1)
			} else {
				klog.InfoS("secret injected into env var", "azurekeyvaultsecret", klog.KObj(akvs), "env", name)
				environ[i] = fmt.Sprintf("%s=%s", name, secret)
			}
		}
	}

	klog.InfoS("starting process with secrets in env vars", "cmd", origCommand, "args", origArgs)
	err = syscall.Exec(origCommand, origArgs, environ)
	if err != nil {
		klog.ErrorS(err, "failed to execute process", "process", origCommand)
		os.Exit(1)
	}

	klog.InfoS("azure key vault env injector successfully injected env variables with secrets")
}
