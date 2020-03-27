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

	"github.com/containers/image/v5/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
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

func getVolumes(useAuthService bool) []corev1.Volume {
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

	return volumes
}

func mutateContainers(containers []corev1.Container, creds map[string]types.DockerAuthConfig) (bool, bool, error) {

	mutated := false
	anyUseAuthService := config.useAuthService

	for i, container := range containers {
		containerOverrideAuthService := false
		containerUseAuthService := config.useAuthService

		log.Infof("found container '%s' to mutate", container.Name)

		var envVars []corev1.EnvVar
		log.Infof("checking for env vars containing '%s' in container %s", envVarReplacementKey, container.Name)
		for _, env := range container.Env {
			if strings.Contains(env.Value, envVarReplacementKey) {
				log.Infof("found env var: %s", env.Value)
				envVars = append(envVars, env)
			}

			if strings.ToUpper(env.Name) == "ENV_INJECTOR_USE_AUTH_SERVICE" {
				containerOverrideAuthService = true
				containerUseAuthService, err := strconv.ParseBool(env.Value)
				if err != nil {
					return false, false, fmt.Errorf("failed to parse container env var override for auth service, error: %+v", err)
				}
				if containerUseAuthService {
					anyUseAuthService = true
				}
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
			// todo: acr is azure specific
			regCred, ok = getAcrCredentials(registryName)
		}

		if !ok {
			log.Infof("did not find credentials to use with registry '%s' - skipping credentials", registryName)
		}

		autoArgs, err := getContainerCmd(container, regCred)
		if err != nil {
			return false, false, fmt.Errorf("failed to get auto cmd, error: %+v", err)
		}

		autoArgsStr := strings.Join(autoArgs, " ")
		log.Infof("using '%s' as arguments for env-injector", autoArgsStr)

		privKey, pubKey, err := newKeyPair()
		if err != nil {
			return false, false, fmt.Errorf("failed to create signing key pair, error: %+v", err)
		}

		signature, err := signPKCS(autoArgsStr, *privKey)
		if err != nil {
			return false, false, fmt.Errorf("failed to sign command args, error: %+v", err)
		}

		publicSigningKey, err := exportRsaPublicKey(pubKey)
		if err != nil {
			return false, false, fmt.Errorf("failed to export public rsa key to pem, error: %+v", err)
		}

		mutated = true

		fullExecPath := filepath.Join(injectorDir, injectorExecutable)
		container.Command = []string{fullExecPath}
		container.Args = autoArgs

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "azure-keyvault-env",
				MountPath: injectorDir,
				ReadOnly:  true,
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
				Name:  "ENV_INJECTOR_ARGS_SIGNATURE",
				Value: base64.StdEncoding.EncodeToString([]byte(signature)),
			},
			{
				Name:  "ENV_INJECTOR_ARGS_KEY",
				Value: base64.StdEncoding.EncodeToString([]byte(publicSigningKey)),
			},
		}...)

		// Do not add env var for using auth service if already exists
		if config.useAuthService && !containerOverrideAuthService {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "ENV_INJECTOR_USE_AUTH_SERVICE",
					Value: "true",
				},
			}...)
		}

		if containerUseAuthService {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "ENV_INJECTOR_AUTH_SERVICE",
					Value: fmt.Sprintf("%s.%s.svc:%s", config.authServiceName, namespace(), config.authServicePort),
				},
				{
					Name:  "ENV_INJECTOR_CA_CERT",
					Value: fmt.Sprintf("%s.%s.svc:%s", config.authServiceName, namespace(), config.caPort),
				},
			}...)
		}

		containers[i] = container
	}

	return mutated, anyUseAuthService, nil
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

	var initContainersUseAuthService bool
	var containersUseAuthService bool

	initContainersMutated, initContainersUseAuthService, err := mutateContainers(podSpec.InitContainers, regCred)
	if err != nil {
		return err
	}

	containersMutated, containersUseAuthService, err := mutateContainers(podSpec.Containers, regCred)
	if err != nil {
		return err
	}

	if initContainersMutated || containersMutated {
		podSpec.InitContainers = append(getInitContainers(), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolumes(initContainersUseAuthService || containersUseAuthService)...)
		log.Info("containers mutated and pod updated with init-container and volumes")
		podsMutatedCounter.Inc()
	} else {
		log.Info("no containers mutated")
	}

	return nil
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
