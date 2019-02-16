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
	"net/http"
	"os"
	"strings"

	whhttp "github.com/slok/kubewebhook/pkg/http"
	"github.com/slok/kubewebhook/pkg/log"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	dockertypes "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"
)

type vaultConfig struct {
	addr       string
	role       string
	path       string
	skipVerify string
	useAgent   bool
}

func getInitContainers(secret *corev1.Secret) []corev1.Container {
	fmt.Fprintln(os.Stdout, "Getting init containers...")
	return []corev1.Container{
		{
			Name:            "copy-azurekeyvault-env",
			Image:           viper.GetString("azurekeyvault_env_image"),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"sh", "-c", "cp /usr/local/bin/azure-keyvault-env /azure-keyvault/"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "azure-keyvault-env",
					MountPath: "/azure-keyvault/",
				},
			},
		},
	}
}

func getVolume() []corev1.Volume {
	fmt.Fprintln(os.Stdout, "Getting volumes...")
	return []corev1.Volume{
		{
			Name: "azure-keyvault-env",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
	}
}

func vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	var podSpec *corev1.PodSpec

	req := whcontext.GetAdmissionRequest(ctx)

	namespace := req.Namespace

	switch v := obj.(type) {
	case *corev1.Pod:
		fmt.Fprintf(os.Stdout, "Found pod '%s' to mutate in namespace '%s'\n", obj.GetName(), namespace)
		podSpec = &v.Spec
	default:
		return false, nil
	}

	fmt.Fprintln(os.Stdout, "Mutating pod...")
	return false, mutatePodSpec(obj, podSpec, namespace)
}

func mutateContainers(containers []corev1.Container, secret *corev1.Secret, registryCreds map[string]string) bool {
	fmt.Fprintln(os.Stdout, "Mutating containers...")
	mutated := false
	for i, container := range containers {
		fmt.Fprintf(os.Stdout, "Found container '%s' to mutate\n", container.Name)

		var envVars []corev1.EnvVar
		fmt.Fprintf(os.Stdout, "Checking for env vars with right prefix in container %s\n", container.Name)
		for _, env := range container.Env {
			if strings.HasPrefix(env.Value, "azurekeyvault#") {
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

		regCred, ok := registryCreds[registryName]

		if ok {
			fmt.Fprintf(os.Stdout, "found credentials to use with registry '%s'\n", registryName)
		} else {
			fmt.Fprintf(os.Stdout, "did not find credentials to use with registry '%s'\n", registryName)
		}

		autoArgs, err := getContainerCmd(container, regCred)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get auto cmd, error: %+v", err)
			continue
		}

		fmt.Fprintf(os.Stdout, "Auto args is %v\n", autoArgs)

		mutated = true

		// args := append(container.Command, container.Args...)

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
				Name: "POD_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
			{
				Name: "AZURE_TENANT_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: "tenant-id",
					},
				},
			},
			{
				Name: "AZURE_CLIENT_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: "client-id",
					},
				},
			},
			{
				Name: "AZURE_CLIENT_SECRET",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: "client-secret",
					},
				},
			},
		}...)

		containers[i] = container
	}

	return mutated
}

func getContainerCmd(container corev1.Container, creds string) ([]string, error) {
	cmd := []string{"/azure-keyvault/azure-keyvault-env"}

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

func getSecretForAzureKeyVault() (*corev1.Secret, error) {
	fmt.Fprintln(os.Stdout, "Getting secret for azure key vault...")

	tenantID := viper.GetString("azure_tenant_id")
	clientID := viper.GetString("azure_client_id")
	clientSecret := viper.GetString("azure_client_secret")
	outputSecretName := viper.GetString("azure_keyvault_secret_name")

	if tenantID == "" || clientID == "" || clientSecret == "" || outputSecretName == "" {
		return nil, fmt.Errorf("env variables for azure key vault credentials not found")
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: outputSecretName,
		},
		StringData: map[string]string{
			"client-id":     clientID,
			"client-secret": clientSecret,
			"tenant-id":     tenantID,
		},
	}, nil
}

func getRegistryCreds(clientset kubernetes.Clientset, podSpec *corev1.PodSpec, namespace string) (map[string]string, error) {
	creds := make(map[string]string)

	var config struct {
		Auths map[string]struct {
			Auth string
		}
	}

	var decoded []byte
	var ok bool
	if podSpec.ImagePullSecrets != nil {
		for _, secret := range podSpec.ImagePullSecrets {
			secret, err := clientset.CoreV1().Secrets(namespace).Get(secret.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}

			switch secret.Type {
			case corev1.SecretTypeDockerConfigJson:
				decoded, ok = secret.Data[corev1.DockerConfigJsonKey]
			default:
				return nil, fmt.Errorf("unable to load image pull secret '%s', only type '%s' is supported", secret.Name, secret.Type)
			}

			if !ok {
				return creds, nil
			}

			if err := json.Unmarshal(decoded, &config); err != nil {
				return creds, err
			}

			// If it's in k8s format, it won't have the surrounding "Auth". Try that too.
			if len(config.Auths) == 0 {
				if err := json.Unmarshal(decoded, &config.Auths); err != nil {
					return creds, err
				}
			}

			for host, entry := range config.Auths {
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
				} //fmt.Sprintf("{ \"username\": \"%s\", \"password\": \"%s\", \"email\": \"%s\" }", authParts[0], authParts[1], "jon@torresdal.net")
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

func mutatePodSpec(obj metav1.Object, podSpec *corev1.PodSpec, namespace string) error {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	keyVaultSecret, err := getSecretForAzureKeyVault()
	if err != nil {
		return err
	}

	registryCreds, err := getRegistryCreds(*clientset, podSpec, namespace)
	if err != nil {
		return err
	}

	initContainersMutated := mutateContainers(podSpec.InitContainers, keyVaultSecret, registryCreds)
	containersMutated := mutateContainers(podSpec.Containers, keyVaultSecret, registryCreds)

	if initContainersMutated || containersMutated {
		if namespace != "" {
			fmt.Fprintf(os.Stdout, "Creating secret in new namespace '%s'...\n", namespace)
			_, err = clientset.CoreV1().Secrets(namespace).Create(keyVaultSecret)
			if err != nil {
				if errors.IsAlreadyExists(err) {
					_, err = clientset.CoreV1().Secrets(namespace).Update(keyVaultSecret)
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}

		podSpec.InitContainers = append(getInitContainers(keyVaultSecret), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolume()...)
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
