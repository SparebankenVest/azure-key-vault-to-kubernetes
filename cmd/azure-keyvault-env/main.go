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
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	vaultSecretv1alpha1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1alpha1"
	clientset "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"
)

const logPrefix = "env-injector:"

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
	log.Printf("%s Log level set to '%s'", logPrefix, logrusLevel.String())
}

func main() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: true,
	})

	setLogLevel()

	log.Debugf("%s azure key vault env injector initializing", logPrefix)
	var vaultService vault.Service

	namespace := os.Getenv("ENV_INJECTOR_POD_NAMESPACE")
	if namespace == "" {
		log.Fatalf("%s current namespace not provided in environment variable env_injector_pod_namespace", logPrefix)
	}

	log.Debugf("%s azure key vault env injector config:", logPrefix)
	log.Debugf("%s namespace: %s", logPrefix, namespace)

	defaultAuth := strings.ToLower(os.Getenv("ENV_INJECTOR_DEFAULT_AUTH"))
	log.Debugf("%s inject default auth: %s", logPrefix, defaultAuth)

	if defaultAuth == "true" {
		log.Debugf("%s reading default auth from host", logPrefix)
		bytes, err := ioutil.ReadFile("/etc/kubernetes/azure.json")
		if err != nil {
			log.Fatalf("%s failed to read cloud config file in an effort to get credentials for azure key vault, error: %+v", logPrefix, err)
		}

		azureConfig := auth.AzureAuthConfig{}
		if err = yaml.Unmarshal(bytes, &azureConfig); err != nil {
			log.Fatalf("%s Unmarshall error: %v", logPrefix, err)
		}

		creds := &vault.ServiceCredentials{
			ClientID:     azureConfig.AADClientID,
			ClientSecret: azureConfig.AADClientSecret,
			TenantID:     azureConfig.TenantID,
		}

		log.Debugf("%s creating client for azure key vault using default auth with clientid '%s'", logPrefix, azureConfig.AADClientID)

		vaultService = vault.NewServiceWithClientCredentials(creds)
	} else {
		log.Debugf("%s creating client for azure key vault using azure credentials supplied to pod", logPrefix)
		vaultService = vault.NewService()
	}

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

		if strings.HasPrefix(value, "azurekeyvault@") {
			secretName := strings.TrimPrefix(value, "azurekeyvault@")

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
		err = syscall.Exec(binary, os.Args[1:], environ)
		if err != nil {
			log.Fatalf("%s failed to exec process '%s': %s", logPrefix, binary, err.Error())
		}
	}

	log.Debugf("%s azure key vault env injector successfully injected env variables with secrets", logPrefix)
	log.Debugf("%s azure key vault env injector", logPrefix)
}

func getSecretFromKeyVault(azureKeyVaultSecret *vaultSecretv1alpha1.AzureKeyVaultSecret, query string, vaultService vault.Service) (string, error) {
	var secretHandler EnvSecretHandler

	switch azureKeyVaultSecret.Spec.Vault.Object.Type {
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeSecret:
		secretHandler = NewAzureKeyVaultSecretHandler(azureKeyVaultSecret, query, vaultService)
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeCertificate:
		secretHandler = NewAzureKeyVaultCertificateHandler(azureKeyVaultSecret, query, vaultService)
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeKey:
		secretHandler = NewAzureKeyVaultKeyHandler(azureKeyVaultSecret, query, vaultService)
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		secretHandler = NewAzureKeyVaultMultiKeySecretHandler(azureKeyVaultSecret, query, vaultService)
	default:
		return "", fmt.Errorf("azure key vault object type '%s' not currently supported", azureKeyVaultSecret.Spec.Vault.Object.Type)
	}
	return secretHandler.Handle()
}
