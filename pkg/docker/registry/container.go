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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"emperror.dev/errors"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// K8s structure keeps information retrieved from POD definition
type ContainerInfo struct {
	clientset        kubernetes.Interface
	Namespace        string
	ImagePullSecrets string
	RegistryAddress  string
	RegistryName     string
	Image            string
	RegistryUsername string
	RegistryPassword string
}

// Collect reads information from k8s and load them into the structure
func (k *ContainerInfo) Collect(container *corev1.Container, podSpec *corev1.PodSpec, credentialProvider credentialprovider.CredentialProvider) error {
	k.Image = k.fixDockerHubImage(container.Image)

	var err error
	found := false
	// Check for registry credentials in imagePullSecrets attached to the pod
	// ImagePullSecrets attached to ServiceAccounts do not have to be considered
	// explicitly as ServiceAccount ImagePullSecrets are automatically attached
	// to a pod.
	for _, imagePullSecret := range podSpec.ImagePullSecrets {
		found, err = k.checkImagePullSecret(k.Namespace, imagePullSecret.Name)
		if err != nil {
			return err
		}

		if found {
			klog.InfoS("found credentials for registry in imagePullSecrets", "registry", k.RegistryName, "namespace", k.Namespace, "pullSecret", imagePullSecret.Name)
			break
		}
	}

	// In case of other docker registry
	if k.RegistryName == "" && k.RegistryAddress == "" {
		registryName := container.Image
		if strings.HasPrefix(registryName, "https://") {
			registryName = strings.TrimPrefix(registryName, "https://")
		}

		registryName = strings.Split(registryName, "/")[0]
		k.RegistryName = registryName
		k.RegistryAddress = fmt.Sprintf("https://%s", registryName)
	}

	// // Clean registry from image
	// k.Image = strings.TrimPrefix(k.Image, fmt.Sprintf("%s/", k.RegistryName))

	if !found {
		// if still no credentials and it is an ACR image, try to get credentials from Azure
		if found, err = getAcrCredentials(k, credentialProvider); err != nil {
			return err
		}

		if !found {
			klog.InfoS("found no credentials for registry, assuming it is public", "registry", k.RegistryAddress)
		}
	}
	return nil
}

func (k *ContainerInfo) checkImagePullSecret(namespace string, secret string) (bool, error) {
	data, err := k.readDockerSecret(namespace, secret)
	if err != nil {
		return false, errors.Wrapf(err, "cannot read imagePullSecret %s.%s", secret, namespace)
	}

	var dockercfg []byte
	keys := []string{corev1.DockerConfigJsonKey, corev1.DockerConfigKey}
	for _, key := range keys {
		if dockercfg = data[key]; dockercfg != nil {
			break
		}
	}

	if dockercfg == nil {
		return false, errors.Errorf("cannot find any dockercfg key %v in imagePullSecret: %s.%s", keys, secret, namespace)
	}

	var dockerCreds DockerCreds
	err = json.Unmarshal(dockercfg, &dockerCreds)
	if err != nil {
		return false, errors.Wrap(err, "cannot unmarshal docker configuration from imagePullSecret")
	}

	found, err := k.parseDockerConfig(dockerCreds)
	return found, err
}

func getAcrCredentials(k *ContainerInfo, credentialProvider credentialprovider.CredentialProvider) (bool, error) {
	if credentialProvider.IsAcrRegistry(k.Image) {
		cred, err := credentialProvider.GetAcrCredentials(k.Image)
		if err != nil {
			return false, fmt.Errorf("failed getting azure acr credentials, error: %w", err)
		}

		klog.V(4).InfoS("found acr credentials to use in cloud config for docker image", "image", k.Image)
		k.RegistryUsername = cred.Username
		k.RegistryPassword = cred.Password
		return true, nil
	}

	klog.V(4).InfoS("no acr credentials found", "registry", k.RegistryAddress)
	return false, nil
}

func (k *ContainerInfo) readDockerSecret(namespace, secretName string) (map[string][]byte, error) {
	secret, err := k.clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (k *ContainerInfo) parseDockerConfig(dockerCreds DockerCreds) (bool, error) {
	for registryName, registryAuth := range dockerCreds.Auths {
		if strings.HasPrefix(registryName, "https://") {
			registryName = strings.TrimPrefix(registryName, "https://")
		}

		// kubectl create secret docker-registry for DockerHub creates
		// registry credentials with API version suffixes, trim it!
		if strings.HasSuffix(registryName, "/v1/") {
			registryName = strings.TrimSuffix(registryName, "/v1/")
		} else if strings.HasSuffix(registryName, "/v2/") {
			registryName = strings.TrimSuffix(registryName, "/v2/")
		}

		registryName = strings.TrimSuffix(registryName, "/")

		if strings.HasPrefix(k.Image, registryName) {
			k.RegistryName = registryName
			if registryAuth.ServerAddress != "" {
				k.RegistryAddress = registryAuth.ServerAddress
			} else {
				k.RegistryAddress = fmt.Sprintf("https://%s", registryName)
			}
			if len(registryAuth.Username) > 0 && len(registryAuth.Password) > 0 {
				// auths.<registry>.username and auths.<registry>.username are present
				// in the config.json, use them
				k.RegistryUsername = registryAuth.Username
				k.RegistryPassword = registryAuth.Password
			} else if len(registryAuth.Auth) > 0 {
				// auths.<registry>.username and auths.<registry>.username are not present
				// in the config.json, fall back to the base64 encoded auths.<registry>.auth field
				// The registry.Auth field contains a base64 encoded string of the format <username>:<password>
				decodedAuth, err := base64.StdEncoding.DecodeString(registryAuth.Auth)
				if err != nil {
					return false, errors.Wrapf(err, "failed to decode auth field for registry %s", registryName)
				}
				auth := strings.Split(string(decodedAuth), ":")
				if len(auth) != 2 {
					return false, errors.Errorf("unexpected number of elements in auth field for registry %s: %d (expected 2)", registryName, len(auth))
				}
				// decodedAuth is something like ":xxx"
				if len(auth[0]) <= 0 {
					return false, errors.Errorf("username element of auth field for registry %s missing", registryName)
				}
				// decodedAuth is something like "xxx:"
				if len(auth[1]) <= 0 {
					return false, errors.Errorf("password element of auth field for registry %s missing", registryName)
				}
				k.RegistryUsername = auth[0]
				k.RegistryPassword = auth[1]
			} else {
				// the auths section has an entry for the registry, but it neither contains
				// username/password fields nor an auth field, fail
				return false, errors.Errorf("found %s in imagePullSecrets but it contains no usable credentials; either username/password fields or an auth field are required", registryName)
			}

			return true, nil
		}
	}

	return false, nil
}

func (k *ContainerInfo) fixDockerHubImage(image string) string {
	slash := strings.Index(image, "/")
	if slash == -1 { // Is it a DockerHub library repository?
		image = "index.docker.io/library/" + image
	} else if !strings.Contains(image[:slash], ".") { // DockerHub organization names can't contain '.'
		image = "index.docker.io/" + image
	} else if strings.HasPrefix(image, "docker.io/") {
		image = "index." + image
	} else {
		return image
	}

	// if in the end there is no RegistryAddress defined it should be a public DockerHub repository
	k.RegistryAddress = "https://index.docker.io"
	k.RegistryName = "index.docker.io"

	return image
}
