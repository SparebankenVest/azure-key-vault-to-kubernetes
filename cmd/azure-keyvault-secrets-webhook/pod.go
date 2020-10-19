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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	authSecretVolumeName  = "akv2k8s-client-cert"
	keyVaultEnvVolumeName = "azure-keyvault-env"
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
				Name:      initContainerVolumeName,
				MountPath: injectorDir,
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
		log.Infof("found container '%s' to mutate", container.Name)

		var envVars []corev1.EnvVar
		log.Infof("checking for env vars containing '%s' in container %s", envVarReplacementKey, container.Name)
		for _, env := range container.Env {
			if strings.Contains(env.Value, envVarReplacementKey) {
				log.Infof("found env var: %s", env.Value)
				envVars = append(envVars, env)
			}

			if strings.ToUpper(env.Name) == "ENV_INJECTOR_DISABLE_AUTH_SERVICE" {
				containerDisabledAuthService, err := strconv.ParseBool(env.Value)
				if err != nil {
					return false, fmt.Errorf("failed to parse container env var override for auth service, error: %+v", err)
				}
				if containerDisabledAuthService {
					log.Infof("container %s has disabled auth service", container.Name)
					useAuthService = false
				}
			}
		}

		if len(envVars) == 0 {
			log.Info("found no env vars in container")
			continue
		}

		autoArgs, err := getContainerCmd(clientset, &container, podSpec, namespace)
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
		log.Debug("signed arguments to prevent override")

		publicSigningKey, err := exportRsaPublicKey(pubKey)
		if err != nil {
			return false, fmt.Errorf("failed to export public rsa key to pem, error: %+v", err)
		}

		log.Debugf("public signing key for argument verification: \n%s", publicSigningKey)

		mutated = true

		fullExecPath := filepath.Join(injectorDir, injectorExecutable)
		log.Debugf("full exec path: %s", fullExecPath)
		container.Command = []string{fullExecPath}
		container.Args = autoArgs
		log.Debugf("container args: %+v", autoArgs)

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      keyVaultEnvVolumeName,
				MountPath: injectorDir,
				ReadOnly:  true,
			},
		}...)
		log.Debugf("mounting volume '%s' to '%s'", keyVaultEnvVolumeName, injectorDir)

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
			{
				Name:  "ENV_INJECTOR_EXEC_DIR",
				Value: injectorDir,
			},
		}...)

		if useAuthService {
			_, err := config.kubeClient.CoreV1().Secrets(namespace).Create(authServiceSecret)
			if err != nil {
				return false, err
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
				// {
				// 	Name: "ENV_INJECTOR_CA_CERT",
				// 	ValueFrom: &corev1.EnvVarSource{
				// 		ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				// 			LocalObjectReference: corev1.LocalObjectReference{
				// 				Name: config.caBundleConfigMapName,
				// 			},
				// 			Key: "caCert",
				// 		},
				// 	},
				// },
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

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("akv2k8s-%s", mutationID),
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(pod, schema.GroupVersionKind{
					Group:   metav1.SchemeGroupVersion.Group,
					Version: metav1.SchemeGroupVersion.Version,
					Kind:    "Pod",
				}),
			},
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
		log.Info("containers mutated and pod updated with init-container and volumes")
		podsMutatedCounter.Inc()
	} else {
		log.Info("no containers mutated")
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
