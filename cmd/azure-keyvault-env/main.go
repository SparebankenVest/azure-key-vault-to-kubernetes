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
	"strings"
	"syscall"

	vaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	vault "github.com/SparebankenVest/azure-keyvault-controller/pkg/azurekeyvault"
	clientset "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/clientset/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func main() {

	// client, err := vault.NewClientWithConfig(vaultapi.DefaultConfig(), role, path)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "failed to create vault client: %s\n", err.Error())
	// 	os.Exit(1)
	// }

	fmt.Println("Starting...")

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		fmt.Fprintf(os.Stderr, "Current namespace not provided in environment variable POD_NAMESPACE")
		os.Exit(1)
	}

	fmt.Printf("Current namespace is '%s'\n", namespace)

	clientID := os.Getenv("AZURE_CLIENT_ID")
	// clientSecret, _ := os.Getenv("AZURE_CLIENT_SECRET")
	// tenantID, _ := os.Getenv("AZURE_TENANT_ID")

	// vaultService := vault.NewServiceFromCredentials(&vault.ServiceCredentials{
	// 	ClientID:     clientID,
	// 	ClientSecret: clientSecret,
	// 	TenantID:     tenantID,
	// })

	vaultService := vault.NewService()
	fmt.Fprintf(os.Stdout, "Azure client ID: '%s'\n", clientID)

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

		if strings.HasPrefix(value, "azurekeyvault#") {

			secretName := strings.TrimPrefix(value, "azurekeyvault#")

			if secretName == "" {
				fmt.Fprintf(os.Stderr, "Error extracting secret name from environment: '%s' not properly formatted", value)
				os.Exit(1)
			}

			keyVaultSecretSpec, err := azureKeyVaultSecretClient.AzurekeyvaultcontrollerV1alpha1().AzureKeyVaultSecrets(namespace).Get(secretName, v1.GetOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting AzureKeyVaultSecret resource '%s', error: %s", secretName, err.Error())
				os.Exit(1)
			}

			secret, err := getSecretFromKeyVault(keyVaultSecretSpec, vaultService)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read secret '%s', error %+v\n", keyVaultSecretSpec.Spec.Vault.Object.Name, err)
				// os.Exit(1)
			}

			if secret == nil {
				fmt.Fprintf(os.Stderr, "secret not found in azure key vault: %s\n", keyVaultSecretSpec.Spec.Vault.Object.Name)
				// os.Exit(1)
			} else {
				if value, ok := secret["key"]; ok {
					environ[i] = fmt.Sprintf("%s=%s", name, value)
				} else {
					fmt.Fprintf(os.Stderr, "key not found: %s\n", "key")
					os.Exit(1)
				}
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
		// binary, err := exec.LookPath(os.Args[1])
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "binary not found: %s\n", os.Args[1])
		// 	os.Exit(1)
		// }
		// cmd := exec.Command(binary, os.Args[1:]...)
		// cmd.Stdout = os.Stdout
		// cmd.Stderr = os.Stderr
		// cmd.Env = environ
		// // cmd.Args = os.Args[1:]
		// fmt.Fprintf(os.Stdout, "\nexecuting process '%v'\n", os.Args[1:])
		// fmt.Fprintf(os.Stdout, "with these env vars '%v'\n", environ)
		// err = cmd.Run()
		// // err = os.Exec(binary, os.Args[1:], environ)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "failed to exec process '%s': %+v\n", binary, err)
		// 	os.Exit(1)
		// }
	}
}

func getSecretFromKeyVault(azureKeyVaultSecret *vaultSecretv1alpha1.AzureKeyVaultSecret, vaultService vault.Service) (map[string]string, error) {
	var secretHandler EnvSecretHandler

	switch azureKeyVaultSecret.Spec.Vault.Object.Type {
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeSecret:
		secretHandler = NewAzureKeyVaultSecretHandler(azureKeyVaultSecret, vaultService)
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeCertificate:
		secretHandler = NewAzureKeyVaultCertificateHandler(azureKeyVaultSecret, vaultService)
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeKey:
		secretHandler = NewAzureKeyVaultKeyHandler(azureKeyVaultSecret, vaultService)
	case vaultSecretv1alpha1.AzureKeyVaultObjectTypeMultiKeyValueSecret:
		secretHandler = NewAzureKeyVaultMultiKeySecretHandler(azureKeyVaultSecret, vaultService)
	default:
		return nil, fmt.Errorf("azure key vault object type '%s' not currently supported", azureKeyVaultSecret.Spec.Vault.Object.Type)
	}

	fmt.Fprintln(os.Stdout, "Getting secret now 0!")
	return secretHandler.Handle()
}
