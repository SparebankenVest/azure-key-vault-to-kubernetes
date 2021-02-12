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
	"k8s.io/klog/v2"
)

const (
	authSecretVolumeName  = "akv2k8s-client-cert"
	keyVaultEnvVolumeName = "azure-keyvault-env"
)

type podWebHook struct {
	clientset                 kubernetes.Interface
	namespace                 string
	mutationID                types.UID
	authServiceSecret         *corev1.Secret
	injectorDir               string
	useAuthService            bool
	authServiceName           string
	authServicePort           string
	authServiceValidationPort string
	caCert                    []byte
	caKey                     []byte
}

// This init-container copies a program to /azure-keyvault/ and
// if default auth copies a read only version of azure config into
// the /azure-keyvault/ folder to use as auth
func (p podWebHook) getInitContainers() []corev1.Container {
	cmd := fmt.Sprintf("cp /usr/local/bin/%s %s", injectorExecutable, p.injectorDir)

	container := corev1.Container{
		Name:            "copy-azurekeyvault-env",
		Image:           viper.GetString("azurekeyvault_env_image"),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", cmd},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      initContainerVolumeName,
				MountPath: p.injectorDir,
			},
		},
	}

	return []corev1.Container{container}
}

func (p podWebHook) getVolumes(authSecret *corev1.Secret) []corev1.Volume {
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

	if p.useAuthService {
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

func (p podWebHook) mutateContainers(containers []corev1.Container, podSpec *corev1.PodSpec) (bool, error) {
	mutated := false

	for i, container := range containers {
		useAuthService := p.useAuthService
		klog.InfoS("found container to mutate", "container", klog.KRef(p.namespace, container.Name))

		var envVars []corev1.EnvVar
		klog.InfoS("checking for env vars to inject", "container", klog.KRef(p.namespace, container.Name))
		for _, env := range container.Env {
			if strings.Contains(env.Value, envVarReplacementKey) {
				klog.InfoS("found env var to inject", "env", env.Value, "container", klog.KRef(p.namespace, container.Name))
				envVars = append(envVars, env)
			}

			if strings.ToUpper(env.Name) == "ENV_INJECTOR_DISABLE_AUTH_SERVICE" {
				containerDisabledAuthService, err := strconv.ParseBool(env.Value)
				if err != nil {
					return false, fmt.Errorf("failed to parse container env var override for auth service, error: %+v", err)
				}
				if containerDisabledAuthService {
					klog.InfoS("container has disabled auth service", "container", klog.KRef(p.namespace, container.Name))
					useAuthService = false
				}
			}
		}

		if len(envVars) == 0 {
			klog.Info("found no env vars to inject", "container", klog.KRef(p.namespace, container.Name))
			continue
		}

		autoArgs, err := getContainerCmd(p.clientset, &container, podSpec, p.namespace)
		if err != nil {
			return false, fmt.Errorf("failed to get auto cmd, error: %+v", err)
		}

		autoArgsStr := strings.Join(autoArgs, " ")
		klog.InfoS("found container arguments to use for env-injector", "cmd", autoArgsStr, "container", klog.KRef(p.namespace, container.Name))

		keys, err := p.createSigningKeys(autoArgsStr, container.Name)
		if err != nil {
			return false, err
		}

		mutated = true

		fullExecPath := filepath.Join(p.injectorDir, injectorExecutable)
		klog.V(4).InfoS("full exec path", "path", fullExecPath, "container", klog.KRef(p.namespace, container.Name))
		container.Command = []string{fullExecPath}
		container.Args = autoArgs

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      keyVaultEnvVolumeName,
				MountPath: p.injectorDir,
				ReadOnly:  true,
			},
		}...)
		klog.V(4).InfoS("mounting volume", "volume", keyVaultEnvVolumeName, "path", p.injectorDir, "container", klog.KRef(p.namespace, container.Name))

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "ENV_INJECTOR_ARGS_SIGNATURE",
				Value: base64.StdEncoding.EncodeToString([]byte(keys.signature)),
			},
			{
				Name:  "ENV_INJECTOR_ARGS_KEY",
				Value: base64.StdEncoding.EncodeToString([]byte(keys.key)),
			},
			{
				Name:  "ENV_INJECTOR_USE_AUTH_SERVICE",
				Value: strconv.FormatBool(useAuthService),
			},
		}...)

		if useAuthService {
			_, err := p.clientset.CoreV1().Secrets(p.namespace).Create(context.TODO(), p.authServiceSecret, metav1.CreateOptions{})
			if err != nil {
				if errors.IsAlreadyExists(err) {
					_, err = p.clientset.CoreV1().Secrets(p.namespace).Update(context.TODO(), p.authServiceSecret, metav1.UpdateOptions{})
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
					Value: fmt.Sprintf("https://%s.%s.svc:%s", p.authServiceName, p.currentNamespace(), p.authServicePort),
				},
				{
					Name:  "ENV_INJECTOR_AUTH_SERVICE_VALIDATION",
					Value: fmt.Sprintf("http://%s.%s.svc:%s", p.authServiceName, p.currentNamespace(), p.authServiceValidationPort),
				},
			}...)
		}

		containers[i] = container
	}

	return mutated, nil
}

type argsSignature struct {
	signature string
	key       string
}

func (p podWebHook) createSigningKeys(autoArgs string, containerName string) (*argsSignature, error) {
	privKey, pubKey, err := newKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing key pair, error: %+v", err)
	}

	signature, err := signPKCS(autoArgs, *privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign command args, error: %+v", err)
	}
	klog.V(4).InfoS("signed arguments to prevent override", "container", klog.KRef(p.namespace, containerName))

	publicSigningKey, err := exportRsaPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to export public rsa key to pem, error: %+v", err)
	}

	klog.V(4).InfoS("public signing key for argument verification", "key", publicSigningKey, "container", klog.KRef(p.namespace, containerName))
	return &argsSignature{
		signature: signature,
		key:       publicSigningKey,
	}, nil
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

func (p podWebHook) mutatePodSpec(pod *corev1.Pod) error {
	podSpec := &pod.Spec

	if p.useAuthService {
		secret, err := createAuthServicePodSecret(pod, p.namespace, p.mutationID, p.caCert, p.caKey)
		if err != nil {
			return err
		}
		p.authServiceSecret = secret
	}

	initContainersMutated, err := p.mutateContainers(podSpec.InitContainers, podSpec)
	if err != nil {
		return err
	}

	containersMutated, err := p.mutateContainers(podSpec.Containers, podSpec)
	if err != nil {
		return err
	}

	if initContainersMutated || containersMutated {
		podSpec.InitContainers = append(p.getInitContainers(), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, p.getVolumes(p.authServiceSecret)...)
		klog.InfoS("containers mutated and pod updated with init-container and volumes", "pod", klog.KRef(p.namespace, pod.Name))
		podsMutatedCounter.Inc()
	} else {
		klog.InfoS("no containers mutated", "pod", klog.KRef(p.namespace, pod.Name))
	}

	return nil
}

func (p podWebHook) currentNamespace() string {
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
