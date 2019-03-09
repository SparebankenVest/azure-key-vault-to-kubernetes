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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	whhttp "github.com/slok/kubewebhook/pkg/http"
	"github.com/slok/kubewebhook/pkg/log"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"

	dockertypes "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"
)

type azureKeyVaultConfig struct {
	customAuth               bool
	customAuthAutoInject     bool
	credentials              *AzureKeyVaultCredentials
	credentialsSecretName    string
	namespace                string
	aadPodBindingLabel       string
	cloudConfigHostPath      string
	cloudConfigContainerPath string
}

var config azureKeyVaultConfig

const envVarReplacementKey = "azurekeyvault@"

// This init-container copies a program to /azure-keyvault and
// if default auth copies a read only version of azure config into
// the /azure-keyvault/ folder to use as auth
func getInitContainers() []corev1.Container {
	cmd := "cp /usr/local/bin/azure-keyvault-env /azure-keyvault/"

	if !config.customAuth {
		cmd = cmd + fmt.Sprintf(" && cp %s %s && ", config.cloudConfigHostPath, config.cloudConfigContainerPath)
		cmd = cmd + fmt.Sprintf("chmod 444 %s", config.cloudConfigContainerPath)
	}

	container := corev1.Container{
		Name:            "copy-azurekeyvault-env",
		Image:           viper.GetString("azurekeyvault_env_image"),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", cmd},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "azure-keyvault-env",
				MountPath: "/azure-keyvault/",
			},
		},
	}

	if !config.customAuth {
		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "azure-config",
				MountPath: config.cloudConfigHostPath,
				ReadOnly:  true,
			},
		}...)
	}

	return []corev1.Container{container}
}

func getVolumes() []corev1.Volume {
	hostPathFile := corev1.HostPathFile

	return []corev1.Volume{
		{
			Name: "azure-keyvault-env",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
		{
			Name: "azure-config",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: config.cloudConfigHostPath,
					Type: &hostPathFile,
				},
			},
		},
	}
}

func vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	req := whcontext.GetAdmissionRequest(ctx)
	config.namespace = req.Namespace
	var pod *corev1.Pod

	switch v := obj.(type) {
	case *corev1.Pod:
		fmt.Fprintf(os.Stdout, "Found pod '%s' to mutate in namespace '%s'\n", obj.GetName(), config.namespace)
		pod = v
	default:
		return false, nil
	}

	return false, mutatePodSpec(pod)
}

func mutateContainers(containers []corev1.Container, creds map[string]string) bool {
	fmt.Fprintln(os.Stdout, "Mutating containers...")
	mutated := false
	for i, container := range containers {
		fmt.Fprintf(os.Stdout, "Found container '%s' to mutate\n", container.Name)

		var envVars []corev1.EnvVar
		fmt.Fprintf(os.Stdout, "Checking for env vars with right prefix in container %s\n", container.Name)
		for _, env := range container.Env {
			if strings.HasPrefix(env.Value, envVarReplacementKey) {
				fmt.Fprintf(os.Stdout, "Found env var: %s\n", env.Value)
				envVars = append(envVars, env)
			}
		}
		if len(envVars) == 0 {
			fmt.Fprintln(os.Stdout, "Found no env vars in container")
			continue
		}

		registryName := ""
		imgParts := strings.Split(container.Image, "/")
		if len(imgParts) >= 2 {
			registryName = imgParts[0]
		}

		regCred, ok := creds[registryName]

		if ok {
			fmt.Fprintf(os.Stdout, "found credentials to use with registry '%s'\n", registryName)
		} else {
			fmt.Fprintf(os.Stdout, "did not find credentials to use with registry '%s' - using default credentials\n", registryName)
			regCred, ok = getAcrCreds(registryName)
		}

		autoArgs, err := getContainerCmd(container, regCred)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get auto cmd, error: %+v", err)
			continue
		}

		fmt.Fprintf(os.Stdout, "Auto args is %v\n", autoArgs)

		mutated = true

		container.Command = []string{"/azure-keyvault/azure-keyvault-env"}
		container.Args = autoArgs

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "azure-keyvault-env",
				MountPath: "/azure-keyvault/",
			},
		}...)

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name: "ENV_INJECTOR_POD_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
			{
				Name:  "ENV_INJECTOR_CUSTOM_AUTH",
				Value: strconv.FormatBool(config.customAuth),
			},
		}...)

		if config.customAuth && config.customAuthAutoInject && config.credentials.CredentialsType != CredentialsTypeManagedIdentitiesForAzureResources {
			container.Env = append(container.Env, *config.credentials.GetEnvVarFromSecret(config.credentialsSecretName)...)
		}

		containers[i] = container
	}

	return mutated
}

func getContainerCmd(container corev1.Container, creds string) ([]string, error) {
	cmd := make([]string, 0)

	cli, err := dockerclient.NewEnvClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client, error: %+v", err)
	}

	// pull image in case its not present on host yet
	imgReader, err := cli.ImagePull(context.Background(), container.Image, dockertypes.ImagePullOptions{
		RegistryAuth: creds,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to pull docker image '%s', error: %+v", container.Image, err)
	}

	defer imgReader.Close()

	inspect, _, err := cli.ImageInspectWithRaw(context.Background(), container.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect docker image '%s', error: %+v", container.Image, err)
	}

	// If container.Command is set it will override both image.Entrypoint AND image.Cmd
	// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
	if container.Command != nil {
		fmt.Fprintf(os.Stdout, "Found container command %v\n", container.Command)
		cmd = append(cmd, container.Command...)
	} else {
		if inspect.Config.Entrypoint != nil {
			fmt.Fprintf(os.Stdout, "Dit not find container command, using Entrypoint %v\n", []string(inspect.Config.Entrypoint))
			cmd = append(cmd, []string(inspect.Config.Entrypoint)...)
		} else {
			if inspect.Config.Cmd != nil {
				fmt.Fprintf(os.Stdout, "Dit not find container command or image Entrypoint, using Cmd from image %v\n", []string(inspect.Config.Cmd))
				cmd = append(cmd, []string(inspect.Config.Cmd)...)
			}
		}
	}

	// If container.Args is set it will override image.Cmd
	if container.Args != nil {
		fmt.Fprintf(os.Stdout, "Found container args (will override any cmd or args from image): %v\n", container.Args)
		cmd = append(cmd, container.Args...)
	} else {
		// if container.Command is set it will override image.Cmd
		if container.Command == nil && inspect.Config.Cmd != nil {
			fmt.Fprintf(os.Stdout, "Did not find any container.Command or container.Args, using Cmd from image: %v\n", []string(inspect.Config.Cmd))
			cmd = append(cmd, []string(inspect.Config.Cmd)...)
		}
	}

	return cmd, nil
}

func getRegistryCreds(clientset kubernetes.Clientset, podSpec *corev1.PodSpec) (map[string]string, error) {
	creds := make(map[string]string)

	var conf struct {
		Auths map[string]struct {
			Auth string
		}
	}

	var decoded []byte
	var ok bool
	if podSpec.ImagePullSecrets != nil {
		for _, secret := range podSpec.ImagePullSecrets {
			secret, err := clientset.CoreV1().Secrets(config.namespace).Get(secret.Name, metav1.GetOptions{})
			if err != nil {
				return creds, err
			}

			switch secret.Type {
			case corev1.SecretTypeDockerConfigJson:
				decoded, ok = secret.Data[corev1.DockerConfigJsonKey]
			default:
				return creds, fmt.Errorf("unable to load image pull secret '%s', only type '%s' is supported", secret.Name, secret.Type)
			}

			if !ok {
				continue
			}

			if err := json.Unmarshal(decoded, &conf); err != nil {
				return creds, err
			}

			// If it's in k8s format, it won't have the surrounding "Auth". Try that too.
			if len(conf.Auths) == 0 {
				if err := json.Unmarshal(decoded, &conf.Auths); err != nil {
					return creds, err
				}
			}

			for host, entry := range conf.Auths {
				decodedAuth, err := base64.StdEncoding.DecodeString(entry.Auth)
				if err != nil {
					return creds, err
				}

				authParts := strings.SplitN(string(decodedAuth), ":", 2)
				if len(authParts) != 2 {
					return creds, fmt.Errorf("decoded credential has wrong number of fields (expected 2, got %d)", len(authParts))
				}

				credsValue := dockertypes.AuthConfig{
					Username: authParts[0],
					Password: authParts[1],
				}
				encodedJSON, err := json.Marshal(credsValue)
				if err != nil {
					return creds, err
				}

				creds[host] = base64.URLEncoding.EncodeToString(encodedJSON)
			}
		}
	}
	return creds, nil
}

func getAcrCreds(host string) (string, bool) {
	if !hostIsAzureContainerRegistry(host) {
		fmt.Fprintf(os.Stdout, "registry host '%s' is not a acr registry\n", host)
		return "", false
	}

	bytes, err := ioutil.ReadFile(config.cloudConfigHostPath)
	if err != nil {
		fmt.Fprintf(os.Stdout, "failed to read azure.json to get default credentials, error: %v\n", err)
		return "", false //creds, fmt.Errorf("failed to read cloud config file in an effort to get credentials for azure key vault, error: %+v", err)
	}

	azureConfig := auth.AzureAuthConfig{}
	if err = yaml.Unmarshal(bytes, &azureConfig); err != nil {
		fmt.Fprintf(os.Stdout, "failed to unmarshall azure config, error: %v\n", err)
		return "", false // creds, fmt.Errorf("Unmarshall error: %v", err)
	}

	var credsValue dockertypes.AuthConfig
	if azureConfig.AADClientID != "" {
		fmt.Fprintf(os.Stdout, "using default credentials for docker registry with clientid: %s\n", azureConfig.AADClientID)
		credsValue = dockertypes.AuthConfig{
			Username: azureConfig.AADClientID,
			Password: azureConfig.AADClientSecret,
		}
	} else {
		fmt.Fprintf(os.Stdout, "aadclientid is not set i azure config, so have no credentials to use\n")
		return "", false // nil, fmt.Errorf("Failed to find credentials for docker registry '%s'", regHost)
	}

	encodedJSON, err := json.Marshal(credsValue)
	if err != nil {
		fmt.Fprintf(os.Stdout, "failed to marshall credentials, error: %v\n", err)
		return "", false // creds, err
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), true
}

func hostIsAzureContainerRegistry(host string) bool {
	for _, v := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.de", ".azurecr.us"} {
		if strings.HasSuffix(host, v) {
			return true
		}
	}
	return false
}

func mutatePodSpec(pod *corev1.Pod) error {
	podSpec := &pod.Spec

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	regCred, err := getRegistryCreds(*clientset, podSpec)
	if err != nil {
		return err
	}

	initContainersMutated := mutateContainers(podSpec.InitContainers, regCred)
	containersMutated := mutateContainers(podSpec.Containers, regCred)

	if initContainersMutated || containersMutated {
		if config.namespace != "" && config.customAuth && config.customAuthAutoInject {
			if config.credentials.CredentialsType == CredentialsTypeManagedIdentitiesForAzureResources {
				if pod.Labels == nil {
					pod.Labels = make(map[string]string)
					pod.Labels["aadpodidbinding"] = config.aadPodBindingLabel
				}
			} else {
				fmt.Fprintf(os.Stdout, "Creating secret in new namespace '%s'...\n", config.namespace)

				keyVaultSecret, err := config.credentials.GetKubernetesSecret(config.credentialsSecretName)
				if err != nil {
					return err
				}

				_, err = clientset.CoreV1().Secrets(config.namespace).Create(keyVaultSecret)
				if err != nil {
					if errors.IsAlreadyExists(err) {
						_, err = clientset.CoreV1().Secrets(config.namespace).Update(keyVaultSecret)
						if err != nil {
							return err
						}
					} else {
						return err
					}
				}
			}
		}

		podSpec.InitContainers = append(getInitContainers(), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolumes()...)
	}

	return nil
}

func initConfig() {
	viper.SetDefault("azurekeyvault_env_image", "spvest/azurekeyvault-env:latest")
	viper.AutomaticEnv()
}

func handlerFor(config mutating.WebhookConfig, mutator mutating.MutatorFunc, logger log.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config, mutator, nil, nil, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	handler, err := whhttp.HandlerFor(webhook)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	return handler
}

func main() {
	fmt.Fprintln(os.Stdout, "Initializing config...")
	initConfig()
	fmt.Fprintln(os.Stdout, "Config initialized")

	logger := &log.Std{Debug: viper.GetBool("debug")}

	config = azureKeyVaultConfig{
		customAuth:               viper.GetBool("CUSTOM_AUTH"),
		customAuthAutoInject:     viper.GetBool("CUSTOM_AUTH_INJECT"),
		credentialsSecretName:    viper.GetString("CUSTOM_AUTH_INJECT_SECRET_NAME"),
		cloudConfigHostPath:      "/etc/kubernetes/azure.json",
		cloudConfigContainerPath: "/azure-keyvault/azure.json",
	}

	if config.customAuth {
		azureCreds, err := NewCredentials()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting credentials: %s", err)
			os.Exit(1)
		}

		config.credentials = azureCreds

		if azureCreds.CredentialsType == CredentialsTypeManagedIdentitiesForAzureResources {
			config.aadPodBindingLabel = viper.GetString("aad_pod_binding_label")
		}
	}

	mutator := mutating.MutatorFunc(vaultSecretsMutator)

	podHandler := handlerFor(mutating.WebhookConfig{Name: "azurekeyvault-secrets-pods", Obj: &corev1.Pod{}}, mutator, logger)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)

	logger.Infof("Listening on :443")
	err := http.ListenAndServeTLS(":443", viper.GetString("tls_cert_file"), viper.GetString("tls_private_key_file"), mux)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serving webhook: %s", err)
		os.Exit(1)
	}
}
