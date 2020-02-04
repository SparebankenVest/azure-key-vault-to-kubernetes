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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/akv2k8s/transformers"
	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	akv "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	logPrefix    = "env-injector:"
	envLookupKey = "@azurekeyvault"
)

func setLogLevel() {
	var logLevel string
	var ok bool

	if logLevel, ok = os.LookupEnv("ENV_INJECTOR_LOG_LEVEL"); !ok {
		logLevel = log.InfoLevel.String()
	}

	logrusLevel, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("%s Error setting log level: %s", logPrefix, err.Error())
	}
	log.SetLevel(logrusLevel)
}

func main() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: true,
	})

	setLogLevel()

	log.Debugf("%s azure key vault env injector initializing", logPrefix)
	namespace := os.Getenv("ENV_INJECTOR_POD_NAMESPACE")
	if namespace == "" {
		log.Fatalf("%s current namespace not provided in environment variable env_injector_pod_namespace", logPrefix)
	}

	log.Debugf("%s namespace: %s", logPrefix, namespace)

	customAuth := strings.ToLower(os.Getenv("ENV_INJECTOR_CUSTOM_AUTH"))
	log.Debugf("%s use custom auth: %s", logPrefix, customAuth)

	var creds *vault.AzureKeyVaultCredentials
	var err error

	if customAuth == "true" {
		log.Debugf("%s getting credentials for azure key vault using azure credentials supplied to pod", logPrefix)

		creds, err = vault.NewAzureKeyVaultCredentialsFromEnvironment()
		if err != nil {
			log.Fatalf("%s failed to get credentials for azure key vault, error %+v", logPrefix, err)
		}
	} else {
		log.Debugf("%s getting credentials for azure key vault using azure credentials from cloud config", logPrefix)
		creds, err = vault.NewAzureKeyVaultCredentialsFromCloudConfig("/azure-keyvault/azure.json")
		if err != nil {
			log.Fatalf("%s failed to get credentials for azure key vault, error %+v", logPrefix, err)
		}
	}

	vaultService := vault.NewService(creds)

	log.Debugf("%s reading azurekeyvaultsecret's referenced in env variables", logPrefix)
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("%s error building kubeconfig: %s", logPrefix, err.Error())
	}

	azureKeyVaultSecretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("%s error building azurekeyvaultsecret clientset: %s", logPrefix, err.Error())
	}

	environ := os.Environ()

	for i, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]

		// e.g. my-akv-secret-name@azurekeyvault?some-sub-key
		if strings.Contains(value, envLookupKey) {
			// e.g. my-akv-secret-name?some-sub-key
			log.Debugf("%s found env var '%s' to get azure key vault secret for", logPrefix, value)
			secretName := strings.Join(strings.Split(value, envLookupKey), "")

			if secretName == "" {
				log.Fatalf("%s error extracting secret name from env variable '%s' - not properly formatted", logPrefix, value)
			}

			var secretQuery string
			if query := strings.Split(secretName, "?"); len(query) > 1 {
				if len(query) > 2 {
					log.Fatalf("%s error extracting secret query from '%s' - has multiple query elements defined with '?' - only one supported", logPrefix, secretName)
				}
				secretName = query[0]
				secretQuery = query[1]
				log.Debugf("%s found query in env var '%s', '%s'", logPrefix, value, secretQuery)
			}

			log.Debugf("%s getting azurekeyvaultsecret resource '%s' from kubernetes", logPrefix, secretName)
			keyVaultSecretSpec, err := azureKeyVaultSecretClient.AzurekeyvaultV1alpha1().AzureKeyVaultSecrets(namespace).Get(secretName, v1.GetOptions{})
			if err != nil {
				log.Fatalf("%s error getting azurekeyvaultsecret resource '%s', error: %s", logPrefix, secretName, err.Error())
			}

			log.Debugf("%s getting secret value for '%s' from azure key vault", logPrefix, keyVaultSecretSpec.Spec.Vault.Object.Name)
			secret, err := getSecretFromKeyVault(keyVaultSecretSpec, secretQuery, vaultService)
			if err != nil {
				log.Fatalf("%s failed to read secret '%s', error %+v", logPrefix, keyVaultSecretSpec.Spec.Vault.Object.Name, err)
			}

			if secret == "" {
				log.Fatalf("%s secret not found in azure key vault: %s", logPrefix, keyVaultSecretSpec.Spec.Vault.Object.Name)
			} else {
				environ[i] = fmt.Sprintf("%s=%s", name, secret)
			}
		}
	}

	if len(os.Args) == 1 {
		log.Fatalf("%s no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly", logPrefix)
	} else {
		binary, err := exec.LookPath(os.Args[1])
		if err != nil {
			log.Fatalf("%s binary not found: %s", logPrefix, os.Args[1])
		}

		// Remove potentially sensitive files
		deleteSensitiveFiles()

		log.Infof("starting process %s %v", binary, os.Args[1:])
		err = syscall.Exec(binary, os.Args[1:], environ)
		if err != nil {
			log.Fatalf("%s failed to exec process '%s': %s", logPrefix, binary, err.Error())
		}

	}

	log.Debugf("%s azure key vault env injector successfully injected env variables with secrets", logPrefix)
	log.Debugf("%s azure key vault env injector", logPrefix)
}

func deleteSensitiveFiles() {
	dirToRemove := "/azure-keyvault/"
	log.Debugf("%s deleting directory '%s'", logPrefix, dirToRemove)
	err := clearDir(dirToRemove)
	if err != nil {
		log.Fatalf("%s error removing directory '%s' : %s", logPrefix, dirToRemove, err.Error())
	}
}

func clearDir(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return err
	}
	for _, file := range files {
		log.Debugf("%s deleting file %s", logPrefix, file)
		err = os.Remove(file)
		if err != nil {
			log.Errorf("%s failed to delete file %s", logPrefix, file)
		}
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
