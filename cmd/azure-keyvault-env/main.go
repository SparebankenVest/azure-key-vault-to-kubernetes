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
	yaml "gopkg.in/yaml.v2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"
)

func main() {
	var vaultService vault.Service

	namespace := os.Getenv("ENV_INJECTOR_POD_NAMESPACE")
	if namespace == "" {
		fmt.Fprintf(os.Stderr, "Current namespace not provided in environment variable POD_NAMESPACE")
		os.Exit(1)
	}

	defaultAuth := strings.ToLower(os.Getenv("ENV_INJECTOR_DEFAULT_AUTH"))

	if defaultAuth == "true" {
		bytes, err := ioutil.ReadFile("/etc/kubernetes/azure.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read cloud config file in an effort to get credentials for azure key vault, error: %+v", err)
			os.Exit(1)
		}

		azureConfig := auth.AzureAuthConfig{}
		if err = yaml.Unmarshal(bytes, &azureConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Unmarshall error: %v", err)
			os.Exit(1)
		}

		azureEnv, err := auth.ParseAzureEnvironment(azureConfig.Cloud)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse azure environment, error: %+v", err)
			os.Exit(1)
		}

		token, err := auth.GetServicePrincipalToken(&azureConfig, azureEnv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get service principal from azure config, error: %+v", err)
			os.Exit(1)
		}

		vaultService = vault.NewServiceWithTokenCredentials(token)
	} else {
		vaultService = vault.NewService()
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building kubeconfig: %s", err.Error())
		os.Exit(1)
	}

	azureKeyVaultSecretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building azureKeyVaultSecret clientset: %s", err.Error())
		os.Exit(1)
	}

	environ := os.Environ()

	for i, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]

		if strings.HasPrefix(value, "azurekeyvault@") {

			secretName := strings.TrimPrefix(value, "azurekeyvault@")

			if secretName == "" {
				fmt.Fprintf(os.Stderr, "Error extracting secret name from environment: '%s' not properly formatted", value)
				os.Exit(1)
			}

			var secretQuery string
			if query := strings.Split(secretName, "?"); len(query) > 1 {
				if len(query) > 2 {
					fmt.Fprintf(os.Stderr, "Error extracting secret name from environment: '%s' has multiple query elements defined with '?'", secretName)
					os.Exit(1)
				}
				secretName = query[0]
				secretQuery = query[1]
			}

			keyVaultSecretSpec, err := azureKeyVaultSecretClient.AzurekeyvaultV1alpha1().AzureKeyVaultSecrets(namespace).Get(secretName, v1.GetOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting AzureKeyVaultSecret resource '%s', error: %s", secretName, err.Error())
				os.Exit(1)
			}

			secret, err := getSecretFromKeyVault(keyVaultSecretSpec, secretQuery, vaultService)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read secret '%s', error %+v\n", keyVaultSecretSpec.Spec.Vault.Object.Name, err)
				// os.Exit(1)
			}

			if secret == "" {
				fmt.Fprintf(os.Stderr, "secret not found in azure key vault: %s\n", keyVaultSecretSpec.Spec.Vault.Object.Name)
				// os.Exit(1)
			} else {
				environ[i] = fmt.Sprintf("%s=%s", name, secret)
			}
		}
	}

	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly")
		os.Exit(1)
	} else {
		binary, err := exec.LookPath(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "binary not found: %s\n", os.Args[1])
			os.Exit(1)
		}
		err = syscall.Exec(binary, os.Args[1:], environ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to exec process '%s': %s\n", binary, err.Error())
			os.Exit(1)
		}
	}
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

	fmt.Fprintln(os.Stdout, "Getting secret now 0!")
	return secretHandler.Handle()
}
