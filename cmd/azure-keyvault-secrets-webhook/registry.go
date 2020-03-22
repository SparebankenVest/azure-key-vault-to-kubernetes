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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/azure/auth"

	dockerref "github.com/docker/distribution/reference"
	dockertypes "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"
)

func getContainerCmd(container corev1.Container, creds string) ([]string, error) {
	var image *dockertypes.ImageInspect
	var err error

	cmd := container.Command

	// If container.Command is set it will override both image.Entrypoint AND image.Cmd
	// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
	if len(cmd) == 0 {
		image, err = getDockerImage(container, creds)
		if err != nil {
			return nil, err
		}

		if image == nil {
			return nil, fmt.Errorf("when getting docker image description for %s, an empty description was returned", container.Image)
		}

		cmd = append(cmd, image.Config.Entrypoint...)

		if len(container.Args) == 0 {
			cmd = append(cmd, image.Config.Cmd...)
		}
	}

	cmd = append(cmd, container.Args...)

	return cmd, nil
}

func getDockerImage(container corev1.Container, creds string) (*dockertypes.ImageInspect, error) {
	timeout := time.Duration(config.dockerPullTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opt := dockertypes.ImagePullOptions{
		RegistryAuth: creds,
	}

	cli, err := dockerclient.NewEnvClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client, error: %+v", err)
	}

	imageTag := "latest"
	imageParts := strings.Split(container.Image, ":")
	if len(imageParts) > 1 {
		imageTag = imageParts[1]
	}

	named, err := dockerref.ParseNormalizedNamed(container.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name, error: %+v", err)
	}

	imageName := named.Name() + ":" + imageTag

	// pull image in case its not present on host yet
	log.Infof("pulling docker image %s to get entrypoint and cmd, timeout is %d seconds", imageName, timeout/time.Second)
	imgReader, err := cli.ImagePull(ctx, imageName, opt)

	if err != nil {
		return nil, fmt.Errorf("failed to pull docker image '%s', error: %+v", imageName, err)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	imgPullOutput, err := ioutil.ReadAll(imgReader)
	log.Debugf("docker pull image output: %s", imgPullOutput)
	// io.Copy(os.Stdout, imgReader)

	log.Infof("docker image %s pulled successfully", imageName)
	defer imgReader.Close()

	log.Infof("inspecting container image %s, looking for entrypoint and cmd", imageName)
	inspect, _, err := cli.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect docker image '%s', error: %+v", imageName, err)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return &inspect, nil
}

func getRegistryCreds(clientset kubernetes.Clientset, podSpec *corev1.PodSpec) (map[string]string, error) {
	creds := make(map[string]string)

	var conf struct {
		Auths map[string]struct {
			Auth string
		}
	}

	var decoded []byte
	var ok bool
	if podSpec.ImagePullSecrets != nil {
		for _, secret := range podSpec.ImagePullSecrets {
			secret, err := clientset.CoreV1().Secrets(config.namespace).Get(secret.Name, metav1.GetOptions{})
			if err != nil {
				return creds, err
			}

			switch secret.Type {
			case corev1.SecretTypeDockerConfigJson:
				decoded, ok = secret.Data[corev1.DockerConfigJsonKey]
			default:
				return creds, fmt.Errorf("unable to load image pull secret '%s', only type '%s' is supported", secret.Name, secret.Type)
			}

			if !ok {
				continue
			}

			if err := json.Unmarshal(decoded, &conf); err != nil {
				return creds, err
			}

			// If it's in k8s format, it won't have the surrounding "Auth". Try that too.
			if len(conf.Auths) == 0 {
				if err := json.Unmarshal(decoded, &conf.Auths); err != nil {
					return creds, err
				}
			}

			for host, entry := range conf.Auths {
				decodedAuth, err := base64.StdEncoding.DecodeString(entry.Auth)
				if err != nil {
					return creds, err
				}

				authParts := strings.SplitN(string(decodedAuth), ":", 2)
				if len(authParts) != 2 {
					return creds, fmt.Errorf("decoded credential has wrong number of fields (expected 2, got %d)", len(authParts))
				}

				credsValue := dockertypes.AuthConfig{
					Username: authParts[0],
					Password: authParts[1],
				}
				encodedJSON, err := json.Marshal(credsValue)
				if err != nil {
					return creds, err
				}

				creds[host] = base64.URLEncoding.EncodeToString(encodedJSON)
			}
		}
	}
	return creds, nil
}

func getAcrCreds(host string) (string, bool) {
	if !hostIsAzureContainerRegistry(host) {
		log.Infof("registry host '%s' is not a acr registry", host)
		return "", false
	}

	bytes, err := ioutil.ReadFile(config.cloudConfigHostPath)
	if err != nil {
		log.Infof("failed to read azure.json to get default acr credentials, error: %v", err)
		return "", false
	}

	azureConfig := auth.AzureAuthConfig{}
	if err = yaml.Unmarshal(bytes, &azureConfig); err != nil {
		log.Infof("failed to unmarshall azure config, error: %v", err)
		return "", false
	}

	var credsValue dockertypes.AuthConfig
	if azureConfig.AADClientID != "" {
		log.Infof("using default credentials for docker registry with clientid: %s", azureConfig.AADClientID)
		credsValue = dockertypes.AuthConfig{
			Username: azureConfig.AADClientID,
			Password: azureConfig.AADClientSecret,
		}
	} else {
		log.Info("aadclientid is not set i azure config, so have no credentials to use")
		return "", false // nil, fmt.Errorf("Failed to find credentials for docker registry '%s'", regHost)
	}

	encodedJSON, err := json.Marshal(credsValue)
	if err != nil {
		log.Errorf("failed to marshall credentials, error: %v\n", err)
		return "", false // creds, err
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), true
}

func hostIsAzureContainerRegistry(host string) bool {
	for _, v := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.de", ".azurecr.us"} {
		if strings.HasSuffix(host, v) {
			return true
		}
	}
	return false
}
