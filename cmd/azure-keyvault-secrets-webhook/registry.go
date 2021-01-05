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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func getContainerCmd(clientset kubernetes.Interface, container *corev1.Container, podSpec *corev1.PodSpec, namespace string) ([]string, error) {
	klog.V(4).InfoS("getting container command for container", "container", klog.KRef(namespace, container.Name))
	cmd := container.Command

	// If container.Command is set it will override both image.Entrypoint AND image.Cmd
	// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
	if len(cmd) == 0 {
		klog.V(4).InfoS("no cmd override in kubernetes for container, checking docker image configuration for entrypoint and cmd", "image", container.Image, "container", klog.KRef(namespace, container.Name))

		imgConfig, err := registry.GetImageConfig(clientset, namespace, container, podSpec, config.cloudConfig)
		if err != nil {
			return nil, err
		}

		cmd = append(cmd, imgConfig.Entrypoint...)

		if len(container.Args) == 0 {
			cmd = append(cmd, imgConfig.Cmd...)
		}
	} else {
		klog.V(4).InfoS("found cmd override in kubernetes for container, no need to inspect docker image configuration", "image", container.Image, "container", klog.KRef(namespace, container.Name))
	}

	cmd = append(cmd, container.Args...)

	return cmd, nil
}
