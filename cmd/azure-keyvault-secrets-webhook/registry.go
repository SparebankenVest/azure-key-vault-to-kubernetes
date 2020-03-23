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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/credentialprovider/azure"
)

func getContainerCmd(container corev1.Container, creds types.DockerAuthConfig) ([]string, error) {
	cmd := container.Command

	// If container.Command is set it will override both image.Entrypoint AND image.Cmd
	// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
	if len(cmd) == 0 {
		opts := imageOptions{
			image:       container.Image,
			credentials: creds,
		}

		config, err := opts.getConfigFromManifest()
		if err != nil {
			return nil, err
		}

		cmd = append(cmd, config.Config.Entrypoint...)

		if len(container.Args) == 0 {
			cmd = append(cmd, config.Config.Cmd...)
		}
	}

	cmd = append(cmd, container.Args...)

	return cmd, nil
}

type imageOptions struct {
	image        string
	credentials  types.DockerAuthConfig
	architecture string
	osChoice     string
}

func (opts *imageOptions) getConfigFromManifest() (*v1.Image, error) {
	log.Infof("timeout: %v", config.dockerPullTimeout)
	timeout := time.Duration(config.dockerPullTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// TODO: what about others like OCI, OpenShift and so on?
	if !strings.HasPrefix(opts.image, "docker://") {
		opts.image = "docker://" + opts.image
	}

	ref, err := alltransports.ParseImageName(opts.image)
	if err != nil {
		return nil, err
	}

	sys := &types.SystemContext{
		OCISharedBlobDirPath: "/tmp",
		DockerAuthConfig:     &opts.credentials,
	}

	if opts.osChoice != "" {
		sys.OSChoice = opts.osChoice
	}

	if opts.architecture != "" {
		sys.ArchitectureChoice = opts.architecture
	}

	abc, err := ref.NewImage(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("error parsing image name %q: %v", opts.image, err)
	}
	config, err := abc.OCIConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error reading OCI-formatted configuration data: %v", err)
	}

	return config, nil
}

func getRegistryCreds(clientset kubernetes.Clientset, podSpec *corev1.PodSpec) (map[string]types.DockerAuthConfig, error) {
	creds := make(map[string]types.DockerAuthConfig)

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

				creds[host] = types.DockerAuthConfig{
					Username: authParts[0],
					Password: authParts[1],
				}
			}
		}
	}
	return creds, nil
}

func getAcrCredentials(host string) (*types.DockerAuthConfig, error) {
	isAcr, wildcardHost := hostIsAzureContainerRegistry(host)

	if !isAcr {
		return nil, errors.New("registry host '%s' is not a acr registry")
	}

	conf := azure.NewACRProvider(&config.cloudConfigHostPath)
	if conf.Enabled() {
		dockerConfList := conf.Provide()
		if len(dockerConfList) > 0 {
			dockerConf := dockerConfList[wildcardHost]
			return &types.DockerAuthConfig{
				Username: dockerConf.Username,
				Password: dockerConf.Password,
			}, nil
		}
	}

	return nil, fmt.Errorf("unable to find acr credentials for %s", host)
}

func hostIsAzureContainerRegistry(host string) (bool, string) {
	for _, v := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.de", ".azurecr.us"} {
		if strings.HasSuffix(host, v) {
			return true, fmt.Sprintf("*%s", v)
		}
	}
	return false, ""
}
