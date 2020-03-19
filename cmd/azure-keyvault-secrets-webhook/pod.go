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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// This init-container copies a program to /azure-keyvault/ and
// if default auth copies a read only version of azure config into
// the /azure-keyvault/ folder to use as auth
func getInitContainers() []corev1.Container {
	fullExecPath := filepath.Join(injectorDir, injectorExecutable)
	cmd := fmt.Sprintf("echo 'Copying %s to %s'", fullExecPath, injectorDir)
	cmd = cmd + fmt.Sprintf(" && cp /usr/local/bin/%s %s", injectorExecutable, injectorDir)

	container := corev1.Container{
		Name:            "copy-azurekeyvault-env",
		Image:           viper.GetString("azurekeyvault_env_image"),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", cmd},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "azure-keyvault-env",
				MountPath: injectorDir,
			},
		},
	}

	return []corev1.Container{container}
}

func getVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "azure-keyvault-env",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
	}

	if useClientCert() {
		volumes = append(volumes, []corev1.Volume{
			{
				Name: "client-cert",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: config.clientCertSecretName,
					},
				},
			},
		}...)
	}

	return volumes
}

func mutateContainers(containers []corev1.Container, creds map[string]string) (bool, error) {
	mutated := false
	for i, container := range containers {
		log.Infof("found container '%s' to mutate", container.Name)

		var envVars []corev1.EnvVar
		log.Infof("checking for env vars containing '%s' in container %s", envVarReplacementKey, container.Name)
		for _, env := range container.Env {
			if strings.Contains(env.Value, envVarReplacementKey) {
				log.Infof("found env var: %s", env.Value)
				envVars = append(envVars, env)
			}
		}
		if len(envVars) == 0 {
			log.Info("found no env vars in container")
			continue
		}

		registryName := ""
		imgParts := strings.Split(container.Image, "/")
		if len(imgParts) >= 2 {
			registryName = imgParts[0]
		}

		regCred, ok := creds[registryName]

		if ok {
			log.Infof("found credentials to use with registry '%s'", registryName)
		} else {
			log.Infof("did not find credentials to use with registry '%s' - getting default credentials", registryName)
			regCred, ok = getAcrCreds(registryName)
		}

		autoArgs, err := getContainerCmd(container, regCred)
		if err != nil {
			return false, fmt.Errorf("failed to get auto cmd, error: %+v", err)
		}

		autoArgsStr := strings.Join(autoArgs, " ")
		log.Infof("using '%s' as arguments for env-injector", autoArgsStr)

		privKey, pubKey, err := newKeyPair()
		if err != nil {
			return false, fmt.Errorf("failed to create signing key pair, error: %+v", err)
		}

		signature, err := signPKCS(autoArgsStr, *privKey)
		if err != nil {
			return false, fmt.Errorf("failed to sign command args, error: %+v", err)
		}

		publicSigningKey, err := exportRsaPublicKey(pubKey)
		if err != nil {
			return false, fmt.Errorf("failed to export public rsa key to pem, error: %+v", err)
		}

		mutated = true

		fullExecPath := filepath.Join(injectorDir, injectorExecutable)
		container.Command = []string{fullExecPath}
		container.Args = autoArgs

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "azure-keyvault-env",
				MountPath: injectorDir,
			},
		}...)

		if useClientCert() {
			container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
				{
					Name:      "client-cert",
					MountPath: clientCertDir,
				},
			}...)
		}

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
			{
				Name:  "ENV_INJECTOR_ARGS_SIGNATURE",
				Value: base64.StdEncoding.EncodeToString([]byte(signature)),
			},
			{
				Name:  "ENV_INJECTOR_ARGS_KEY",
				Value: publicSigningKey,
			},
			{
				Name:  "ENV_INJECTOR_HAS_CLIENT_CERT",
				Value: strconv.FormatBool(useClientCert()),
			},
			{
				Name:  "ENV_INJECTOR_AUTH_SERVICE",
				Value: fmt.Sprintf("%s.%s.svc:%s", config.webhookAuthServiceName, namespace(), config.webhookAuthServicePort),
			},
		}...)

		if config.customAuth && config.customAuthAutoInject && config.credentials.CredentialsType != CredentialsTypeManagedIdentitiesForAzureResources {
			container.Env = append(container.Env, *config.credentials.GetEnvVarFromSecret(config.credentialsSecretName)...)
		}

		containers[i] = container
	}

	return mutated, nil
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

	initContainersMutated, err := mutateContainers(podSpec.InitContainers, regCred)
	if err != nil {
		return err
	}

	containersMutated, err := mutateContainers(podSpec.Containers, regCred)
	if err != nil {
		return err
	}

	if initContainersMutated || containersMutated {
		if config.namespace != "" && config.customAuth && config.customAuthAutoInject {
			if config.credentials.CredentialsType == CredentialsTypeManagedIdentitiesForAzureResources {
				if pod.Labels == nil {
					pod.Labels = make(map[string]string)
					pod.Labels["aadpodidbinding"] = config.aadPodBindingLabel
				}
			} else {
				log.Infof("creating secret in new namespace '%s'...", config.namespace)

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

		if config.namespace != "" && useClientCert() {
			log.Infof("creating client cert secret in new namespace '%s'...", config.namespace)

			clientCertSecret, err := createClientCertSecret(config.clientCertSecretName)
			if err != nil {
				return err
			}

			_, err = clientset.CoreV1().Secrets(config.namespace).Create(clientCertSecret)
			if err != nil {
				if errors.IsAlreadyExists(err) {
					_, err = clientset.CoreV1().Secrets(config.namespace).Update(clientCertSecret)
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}

		podSpec.InitContainers = append(getInitContainers(), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolumes()...)
		log.Info("containers mutated and pod updated with init-container and volumes")
		podsMutatedCounter.Inc()
	} else {
		log.Info("no containers mutated")
	}

	return nil
}

func createClientCertSecret(secretName string) (*corev1.Secret, error) {
	clientCert, err := ioutil.ReadFile(config.clientCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client cert file from %s, error: %+v", config.clientCertFile, err)
	}

	clientKey, err := ioutil.ReadFile(config.clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key file from %s, error: %+v", config.clientKeyFile, err)
	}

	caCert, err := ioutil.ReadFile(config.caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca cert file from %s, error: %+v", config.caFile, err)
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		StringData: map[string]string{
			"clientCert": string(clientCert),
			"clientKey":  string(clientKey),
			"caCert":     string(caCert),
		},
	}, nil
}

func useClientCert() bool {
	return !config.customAuth || (config.customAuth && !config.customAuthAutoInject)
}

func namespace() string {
	if ns, ok := os.LookupEnv("POD_NAMESPACE"); ok {
		return ns
	}

	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return "default"
}
