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
	"encoding/json"
	"io/ioutil"
	"strings"

	"emperror.dev/errors"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	dockerTypes "github.com/docker/docker/api/types"
	"github.com/heroku/docker-registry-client/registry"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type DockerCreds struct {
	Auths map[string]dockerTypes.AuthConfig `json:"auths"`
}

// GetImageConfig returns entrypoint and command of container
func GetImageConfig(clientset kubernetes.Interface, namespace string, container *corev1.Container, podSpec *corev1.PodSpec, credentialProvider credentialprovider.CredentialProvider) (*imagev1.ImageConfig, error) {
	containerInfo := ContainerInfo{Namespace: namespace, clientset: clientset}

	err := containerInfo.Collect(container, podSpec, credentialProvider)
	if err != nil {
		return nil, err
	}

	imageConfig, err := getImageBlob(containerInfo)
	return imageConfig, err
}

// GetImageBlob download image blob from registry
func getImageBlob(container ContainerInfo) (*imagev1.ImageConfig, error) {
	imageName, reference := parseContainerImage(container.Image)

	hub, err := registry.New(container.RegistryAddress, container.RegistryUsername, container.RegistryPassword)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create client for doker registry")
	}

	manifest, err := hub.ManifestV2(imageName, reference)
	if err != nil {
		return nil, errors.Wrap(err, "cannot download manifest for docker image")
	}

	reader, err := hub.DownloadBlob(imageName, manifest.Config.Digest)
	if err != nil {
		return nil, errors.Wrap(err, "cannot download blob from docker manifest")
	}

	defer reader.Close()

	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read blob from docker manifest")
	}

	var imageMetadata imagev1.Image
	err = json.Unmarshal(b, &imageMetadata)
	if err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal BlobResponse JSON from docker manifest")
	}

	return &imageMetadata.Config, nil
}

// parseContainerImage returns image and reference
func parseContainerImage(image string) (string, string) {
	var split []string

	if strings.Contains(image, "@") {
		split = strings.SplitN(image, "@", 2)
		subsplit := strings.SplitN(split[0], ":", 2)
		if len(subsplit) > 1 {
			split[0] = subsplit[0]
		}
	} else {
		split = strings.SplitN(image, ":", 2)
	}

	imageName := split[0]
	reference := "latest"

	if len(split) > 1 {
		reference = split[1]
	}

	return imageName, reference
}
