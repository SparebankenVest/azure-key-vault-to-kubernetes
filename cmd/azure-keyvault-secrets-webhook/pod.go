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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/cmd/azure-keyvault-secrets-webhook/auth"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/docker/registry"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
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
	injectorDir               string
	authService               *auth.AuthService
	useAuthService            bool
	authServiceName           string
	authServicePort           string
	authServiceValidationPort string
	registry                  registry.ImageRegistry
}

// This init-container copies a program to /azure-keyvault/ and
// if default auth copies a read only version of azure config into
// the /azure-keyvault/ folder to use as auth
func (p podWebHook) getInitContainers() []corev1.Container {
	cmd := fmt.Sprintf("cp /usr/local/bin/%s %s", injectorExecutable, p.injectorDir)

	container := corev1.Container{
		Name:            "copy-azurekeyvault-env",
		Image:           viper.GetString("azurekeyvault_env_image"),
		ImagePullPolicy: corev1.PullPolicy(viper.GetString("webhook_container_image_pull_policy")),
		Command:         []string{"sh", "-c", cmd},
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
			ReadOnlyRootFilesystem: &[]bool{viper.GetBool("webhook_container_security_context_read_only")}[0],
			RunAsNonRoot:           &[]bool{viper.GetBool("webhook_container_security_context_non_root")}[0],
			Privileged:             &[]bool{viper.GetBool("webhook_container_security_context_privileged")}[0],
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      initContainerVolumeName,
				MountPath: p.injectorDir,
			},
		},
	}
	if viper.IsSet("webhook_container_security_context_allow_privilege_escalation") {
		container.SecurityContext.AllowPrivilegeEscalation = &[]bool{viper.GetBool("webhook_container_security_context_allow_privilege_escalation")}[0]
	}
	if viper.IsSet("webhook_container_security_context_user_uid") {
		container.SecurityContext.RunAsUser = &[]int64{viper.GetInt64("webhook_container_security_context_user_uid")}[0]
	}
	if viper.IsSet("webhook_container_security_context_group_gid") {
		container.SecurityContext.RunAsGroup = &[]int64{viper.GetInt64("webhook_container_security_context_group_gid")}[0]
	}
	if viper.IsSet("webhook_container_security_context_seccomp_runtime_default") && viper.GetBool("webhook_container_security_context_seccomp_runtime_default") {
		container.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		}
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

func (p podWebHook) mutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, authServiceSecret *corev1.Secret) (bool, error) {
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

		autoArgs, err := getContainerCmd(ctx, p.clientset, &container, podSpec, p.namespace, p.registry)
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
		}...)

		if useAuthService {
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
					Name:  "ENV_INJECTOR_AUTH_SERVICE",
					Value: fmt.Sprintf("https://%s.%s.svc:%s", p.authServiceName, p.currentNamespace(), p.authServicePort),
				},
				{
					Name:  "ENV_INJECTOR_AUTH_SERVICE_VALIDATION",
					Value: fmt.Sprintf("http://%s.%s.svc:%s", p.authServiceName, p.currentNamespace(), p.authServiceValidationPort),
				},
				{
					Name:  "ENV_INJECTOR_AUTH_SERVICE_SECRET",
					Value: authServiceSecret.Name,
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

func (p podWebHook) mutatePodSpec(ctx context.Context, pod *corev1.Pod) error {
	var authServiceSecret *corev1.Secret
	var err error
	podSpec := &pod.Spec

	if p.useAuthService {
		klog.InfoS("creating client certificate to use with auth service", klog.KRef(p.namespace, pod.Name))
		authServiceSecret, err = p.authService.NewPodSecret(pod, p.namespace, p.mutationID)
		if err != nil {
			return err
		}
	}

	if p.useAuthService && (len(podSpec.InitContainers) > 0 || len(podSpec.Containers) > 0) {
		klog.InfoS("create authentication service secret", klog.KRef(p.namespace, pod.Name))
		_, err := p.clientset.CoreV1().Secrets(p.namespace).Create(context.TODO(), authServiceSecret, metav1.CreateOptions{})
		if err != nil {
			if errors.IsAlreadyExists(err) {
				_, err = p.clientset.CoreV1().Secrets(p.namespace).Update(context.TODO(), authServiceSecret, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	klog.InfoS("mutate init-containers", klog.KRef(p.namespace, pod.Name))
	initContainersMutated, err := p.mutateContainers(ctx, podSpec.InitContainers, podSpec, authServiceSecret)
	if err != nil {
		return err
	}

	klog.InfoS("mutate containers", klog.KRef(p.namespace, pod.Name))
	containersMutated, err := p.mutateContainers(ctx, podSpec.Containers, podSpec, authServiceSecret)
	if err != nil {
		return err
	}

	if initContainersMutated || containersMutated {
		podSpec.InitContainers = append(p.getInitContainers(), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, p.getVolumes(authServiceSecret)...)
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

	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return "default"
}
