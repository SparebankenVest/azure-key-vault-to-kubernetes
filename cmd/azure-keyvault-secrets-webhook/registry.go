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
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/docker/registry"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

func getContainerCmd(clientset kubernetes.Interface, container *corev1.Container, podSpec *corev1.PodSpec, namespace string) ([]string, error) {
	log.Debugf("getting container command for container '%s'", container.Name)
	cmd := container.Command

	// If container.Command is set it will override both image.Entrypoint AND image.Cmd
	// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
	if len(cmd) == 0 {
		log.Debugf("no cmd override in kubernetes for container %s, checking docker image configuration for entrypoint and cmd for %s", container.Name, container.Image)

		imgConfig, err := registry.GetImageConfig(clientset, namespace, container, podSpec, config.cloudConfigHostPath)
		if err != nil {
			return nil, err
		}

		cmd = append(cmd, imgConfig.Entrypoint...)

		if len(container.Args) == 0 {
			cmd = append(cmd, imgConfig.Cmd...)
		}
	} else {
		log.Debugf("found cmd override in kubernetes for container %s, no need to inspect docker image configuration for %s", container.Name, container.Image)
	}

	cmd = append(cmd, container.Args...)

	return cmd, nil
}
