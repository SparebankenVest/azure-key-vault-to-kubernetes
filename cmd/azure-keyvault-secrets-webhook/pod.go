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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	authSecretVolumeName  = "akv2k8s-client-cert"
	keyVaultEnvVolumeName = "azure-keyvault-env"
)

// This init-container copies a program to /azure-keyvault/ and
// if default auth copies a read only version of azure config into
// the /azure-keyvault/ folder to use as auth
func getInitContainers() []corev1.Container {
	cmd := fmt.Sprintf("cp /usr/local/bin/%s %s", injectorExecutable, config.injectorDir)

	container := corev1.Container{
		Name:            "copy-azurekeyvault-env",
		Image:           viper.GetString("azurekeyvault_env_image"),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", cmd},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      initContainerVolumeName,
				MountPath: config.injectorDir,
			},
		},
	}

	return []corev1.Container{container}
}

func getVolumes(authSecret *corev1.Secret) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: keyVaultEnvVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
	}

	if config.useAuthService {
		mode := int32(420)
		volumes = append(volumes, []corev1.Volume{
			{
				Name: authSecretVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  authSecret.Name,
						DefaultMode: &mode,
					},
				},
			},
		}...)
	}

	return volumes
}

func mutateContainers(clientset kubernetes.Interface, containers []corev1.Container, podSpec *corev1.PodSpec, namespace string, authServiceSecret *corev1.Secret) (bool, error) {
	mutated := false

	for i, container := range containers {
		useAuthService := config.useAuthService
		klog.InfoS("found container to mutate", "container", klog.KRef(namespace, container.Name))

		var envVars []corev1.EnvVar
		klog.InfoS("checking for env vars to inject", "container", klog.KRef(namespace, container.Name))
		for _, env := range container.Env {
			if strings.Contains(env.Value, envVarReplacementKey) {
				klog.InfoS("found env var to inject", "env", env.Value, "container", klog.KRef(namespace, container.Name))
				envVars = append(envVars, env)
			}

			if strings.ToUpper(env.Name) == "ENV_INJECTOR_DISABLE_AUTH_SERVICE" {
				containerDisabledAuthService, err := strconv.ParseBool(env.Value)
				if err != nil {
					return false, fmt.Errorf("failed to parse container env var override for auth service, error: %+v", err)
				}
				if containerDisabledAuthService {
					klog.InfoS("container has disabled auth service", "container", klog.KRef(namespace, container.Name))
					useAuthService = false
				}
			}
		}

		if len(envVars) == 0 {
			klog.Info("found no env vars to inject", "container", klog.KRef(namespace, container.Name))
			continue
		}

		autoArgs, err := getContainerCmd(clientset, &container, podSpec, namespace)
		if err != nil {
			return false, fmt.Errorf("failed to get auto cmd, error: %+v", err)
		}

		autoArgsStr := strings.Join(autoArgs, " ")
		klog.InfoS("found container arguments to use for env-injector", "cmd", autoArgsStr, "container", klog.KRef(namespace, container.Name))

		privKey, pubKey, err := newKeyPair()
		if err != nil {
			return false, fmt.Errorf("failed to create signing key pair, error: %+v", err)
		}

		signature, err := signPKCS(autoArgsStr, *privKey)
		if err != nil {
			return false, fmt.Errorf("failed to sign command args, error: %+v", err)
		}
		klog.V(4).InfoS("signed arguments to prevent override", "container", klog.KRef(namespace, container.Name))

		publicSigningKey, err := exportRsaPublicKey(pubKey)
		if err != nil {
			return false, fmt.Errorf("failed to export public rsa key to pem, error: %+v", err)
		}

		klog.V(4).InfoS("public signing key for argument verification", "key", publicSigningKey, "container", klog.KRef(namespace, container.Name))

		mutated = true

		fullExecPath := filepath.Join(config.injectorDir, injectorExecutable)
		klog.V(4).InfoS("full exec path", "path", fullExecPath, "container", klog.KRef(namespace, container.Name))
		container.Command = []string{fullExecPath}
		container.Args = autoArgs

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      keyVaultEnvVolumeName,
				MountPath: config.injectorDir,
				ReadOnly:  true,
			},
		}...)
		klog.V(4).InfoS("mounting volume", "volume", keyVaultEnvVolumeName, "path", config.injectorDir, "container", klog.KRef(namespace, container.Name))

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "ENV_INJECTOR_ARGS_SIGNATURE",
				Value: base64.StdEncoding.EncodeToString([]byte(signature)),
			},
			{
				Name:  "ENV_INJECTOR_ARGS_KEY",
				Value: base64.StdEncoding.EncodeToString([]byte(publicSigningKey)),
			},
			{
				Name:  "ENV_INJECTOR_USE_AUTH_SERVICE",
				Value: strconv.FormatBool(useAuthService),
			},
		}...)

		if useAuthService {
			_, err := config.kubeClient.CoreV1().Secrets(namespace).Create(context.TODO(), authServiceSecret, metav1.CreateOptions{})
			if err != nil {
				if errors.IsAlreadyExists(err) {
					_, err = config.kubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), authServiceSecret, metav1.UpdateOptions{})
					if err != nil {
						return false, err
					}
				} else {
					return false, err
				}
			}

			container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
				{
					Name:      authSecretVolumeName,
					MountPath: clientCertDir,
					ReadOnly:  true,
				},
			}...)

			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "ENV_INJECTOR_CLIENT_CERT_DIR",
					Value: clientCertDir,
				},
				{
					Name: "ENV_INJECTOR_POD_NAMESPACE",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.namespace",
						},
					},
				},
				{
					Name: "ENV_INJECTOR_POD_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.name",
						},
					},
				},
				{
					Name:  "ENV_INJECTOR_AUTH_SERVICE",
					Value: fmt.Sprintf("%s.%s.svc:%s", config.authServiceName, currentNamespace(), config.authServicePort),
				},
			}...)
		}

		containers[i] = container
	}

	return mutated, nil
}

func createAuthServicePodSecret(pod *corev1.Pod, namespace string, mutationID types.UID, caCert, caKey []byte) (*corev1.Secret, error) {
	// Create secret containing CA cert and mTLS credentials

	clientCert, err := generateClientCert(mutationID, 24, caCert, caKey)
	if err != nil {
		return nil, err
	}

	value := map[string][]byte{
		"ca.crt":  clientCert.CA,
		"tls.crt": clientCert.Crt,
		"tls.key": clientCert.Key,
	}

	name := pod.GetName()
	ownerReferences := pod.GetOwnerReferences()
	if name == "" {
		if len(ownerReferences) > 0 {
			if strings.Contains(ownerReferences[0].Name, "-") {
				generateNameSlice := strings.Split(ownerReferences[0].Name, "-")
				name = strings.Join(generateNameSlice[:len(generateNameSlice)-1], "-")
			} else {
				name = ownerReferences[0].Name
			}
		}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("akv2k8s-%s", name),
			Namespace:       namespace,
			OwnerReferences: ownerReferences,
		},
		Type: corev1.SecretTypeTLS,
		Data: value,
	}

	return secret, nil
}

func mutatePodSpec(pod *corev1.Pod, namespace string, mutationID types.UID) error {
	podSpec := &pod.Spec

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	var authServiceSecret *corev1.Secret
	if config.useAuthService {
		authServiceSecret, err = createAuthServicePodSecret(pod, namespace, mutationID, config.caCert, config.caKey)
		if err != nil {
			return err
		}
	}

	initContainersMutated, err := mutateContainers(clientset, podSpec.InitContainers, podSpec, namespace, authServiceSecret)
	if err != nil {
		return err
	}

	containersMutated, err := mutateContainers(clientset, podSpec.Containers, podSpec, namespace, authServiceSecret)
	if err != nil {
		return err
	}

	if initContainersMutated || containersMutated {
		podSpec.InitContainers = append(getInitContainers(), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolumes(authServiceSecret)...)
		klog.InfoS("containers mutated and pod updated with init-container and volumes", "pod", klog.KRef(namespace, pod.Name))
		podsMutatedCounter.Inc()
	} else {
		klog.InfoS("no containers mutated", "pod", klog.KRef(namespace, pod.Name))
	}

	return nil
}

func currentNamespace() string {
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
