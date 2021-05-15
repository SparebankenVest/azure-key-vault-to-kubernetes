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

package registry

import (

	// force init of azure-container-registry-config flag
	_ "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	_ "github.com/vdemeester/k8s-pkg-credentialprovider/azure"
)

// func TestParsingRegistryAddress(t *testing.T) {
// 	tests := []struct {
// 		container       *corev1.Container
// 		podSpec         *corev1.PodSpec
// 		registryAddress string
// 	}{
// 		{
// 			container: &corev1.Container{
// 				Image: "foo:bar",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://index.docker.io",
// 		},
// 		{
// 			container: &corev1.Container{
// 				Image: "foo",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://index.docker.io",
// 		},
// 		{
// 			container: &corev1.Container{
// 				Image: "library/foo:latest",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://index.docker.io",
// 		},
// 		{
// 			container: &corev1.Container{
// 				Image: "index.docker.io/foo:latest",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://index.docker.io",
// 		},
// 		{
// 			container: &corev1.Container{
// 				Image: "foo:bar",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://index.docker.io",
// 		},
// 		{
// 			container: &corev1.Container{
// 				Image: "docker.io/foo:bar",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://index.docker.io",
// 		},
// 		{
// 			container: &corev1.Container{
// 				Image: "docker.pkg.github.com/banzaicloud/bank-vaults/vault-env:0.6.0",
// 			},
// 			podSpec:         &corev1.PodSpec{},
// 			registryAddress: "https://docker.pkg.github.com",
// 		},
// 	}

// 	for _, test := range tests {
// 		containerInfo := ContainerInfo{}

// 		err := containerInfo.Collect(test.container, test.podSpec, credentialprovider.CloudConfigCredentialProvider{})
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		assert.Equal(t, test.registryAddress, containerInfo.RegistryAddress)
// 	}
// }

// func TestParsingACRImage(t *testing.T) {
// 	prov := credentialprovider.FakeCloudConfigProvider()
// 	dockerCred := credentialprovider.NewAcrDockerProvider(prov)
// 	k8sCredentialProvider.RegisterCredentialProvider("akv2k8s", dockerCred)

// 	sa := &v1.ServiceAccount{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name:      "default",
// 			Namespace: "test-ns",
// 		},
// 	}

// 	kubeClient := fake.NewSimpleClientset(sa)

// 	containerInfo := containerInfo{
// 		Image:              "dokken.azurecr.io/rabbitmq:3.8.8-management-alpine",
// 		ImagePullSecrets:   []string{},
// 		Namespace:          "test-ns",
// 		ServiceAccountName: "",
// 	}

// 	_, err := getImageConfig(context.Background(), kubeClient, containerInfo, ImageRegistryOptions{})
// 	if err != nil {
// 		t.Error(err)
// 	}

// }

// func TestParsingACRImage2(t *testing.T) {
// 	credProvider, err := credentialprovider.FakeEnvironmentCredentialProvider()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	tests := []struct {
// 		container *corev1.Container
// 		podSpec   *corev1.PodSpec
// 		provider  credentialprovider.EnvironmentCredentialProvider
// 	}{
// 		{
// 			container: &corev1.Container{
// 				Image: "akv2k8s.azurecr.io/foo:bar",
// 			},
// 			podSpec:  &corev1.PodSpec{},
// 			provider: credProvider,
// 		},
// 	}

// 	for _, test := range tests {
// 		containerInfo := ContainerInfo{}

// 		err := containerInfo.Collect(test.container, test.podSpec, test.provider)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		// assert.Equal(t, test.registryAddress, containerInfo.RegistryAddress)
// 	}
// }

// func TestParseContainerImage(t *testing.T) {
// 	tests := []struct {
// 		image string
// 		repo  string
// 		tag   string
// 	}{
// 		{
// 			image: "docker-repo.banana.xyz/testing/skaffold-python-example:508954f-dirty@sha256:96b77fc06c9cbd5227eb8538020c6e458a259d17ccb2ec1aea5fe8261a61fff7",
// 			repo:  "docker-repo.banana.xyz/testing/skaffold-python-example",
// 			tag:   "sha256:96b77fc06c9cbd5227eb8538020c6e458a259d17ccb2ec1aea5fe8261a61fff7",
// 		},
// 		{
// 			image: "docker-repo.banana.xyz/testing/skaffold-python-example@sha256:96b77fc06c9cbd5227eb8538020c6e458a259d17ccb2ec1aea5fe8261a61fff7",
// 			repo:  "docker-repo.banana.xyz/testing/skaffold-python-example",
// 			tag:   "sha256:96b77fc06c9cbd5227eb8538020c6e458a259d17ccb2ec1aea5fe8261a61fff7",
// 		},
// 		{
// 			image: "alpine:latest",
// 			repo:  "alpine",
// 			tag:   "latest",
// 		},
// 		{
// 			image: "alpine",
// 			repo:  "alpine",
// 			tag:   "latest",
// 		},
// 	}

// 	for _, test := range tests {
// 		repo, tag := parseContainerImage(test.image)
// 		assert.Equal(t, test.repo, repo, test.image)
// 		assert.Equal(t, test.tag, tag, test.image)
// 	}
// }
