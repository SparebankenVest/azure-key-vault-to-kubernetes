// Copyright © 2021 Jon Arild Tørresdal
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
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure/credentialprovider"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/patrickmn/go-cache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// ImageRegistry is a docker registry
type ImageRegistry interface {
	GetImageConfig(
		ctx context.Context,
		clientset kubernetes.Interface,
		namespace string,
		container *corev1.Container,
		podSpec *corev1.PodSpec,
		opt ImageRegistryOptions) (*v1.Config, error)
}

type ImageRegistryOptions struct {
	SkipVerify bool
}

// Registry impl
type Registry struct {
	authType           string
	imageCache         *cache.Cache
	credentialProvider credentialprovider.CredentialProvider
}

// NewRegistry creates and initializes registry
func NewRegistry(authType string, credentialProvider credentialprovider.CredentialProvider) ImageRegistry { //, credentialProvider credentialprovider.CredentialProvider
	return &Registry{
		authType:           authType,
		imageCache:         cache.New(cache.NoExpiration, cache.NoExpiration),
		credentialProvider: credentialProvider,
	}
}

// IsAllowedToCache checks that information about Docker image can be cached
// base on image name and container PullPolicy
func IsAllowedToCache(container *corev1.Container) bool {
	if container.ImagePullPolicy == corev1.PullAlways {
		return false
	}

	reference, err := name.ParseReference(container.Image)
	if err != nil {
		return false
	}

	return reference.Identifier() != "latest"
}

// GetImageConfig returns entrypoint and command of container
func (r *Registry) GetImageConfig(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	container *corev1.Container,
	podSpec *corev1.PodSpec,
	opt ImageRegistryOptions) (*v1.Config, error) {
	allowToCache := IsAllowedToCache(container)
	if allowToCache {
		if imageConfig, cacheHit := r.imageCache.Get(container.Image); cacheHit {
			klog.InfoS("found image in cache", "image", container.Image)
			return imageConfig.(*v1.Config), nil
		}
	}

	containerInfo := containerInfo{
		Namespace:          namespace,
		ServiceAccountName: podSpec.ServiceAccountName,
		Image:              container.Image,
	}
	for _, imagePullSecret := range podSpec.ImagePullSecrets {
		containerInfo.ImagePullSecrets = append(containerInfo.ImagePullSecrets, imagePullSecret.Name)
	}

	remoteOptions, err := getContainerRegistryRemoteOptions(ctx, client, containerInfo, r.authType, opt, r.credentialProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote options: %w", err)
	}

	imageConfig, err := getImageConfig(containerInfo, remoteOptions)
	if imageConfig != nil && allowToCache {
		r.imageCache.Set(container.Image, imageConfig, cache.DefaultExpiration)
	}

	return imageConfig, err
}

// getContainerRegistryRemoteOptions get container registry remote option
func getContainerRegistryRemoteOptions(ctx context.Context, client kubernetes.Interface, container containerInfo, authType string, opt ImageRegistryOptions, r credentialprovider.CredentialProvider) ([]remote.Option, error) {
	ref, err := name.ParseReference(container.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}
	registry := ref.Context().Registry.Name()

	klog.InfoS("using registry", "imageRegistry", registry)

	authChain := new(authn.Keychain)
	switch authType {
	case "azureCloudConfig":
		klog.InfoS("using cloudConfig for registry authentication", "config.authType", authType)
		dockerConfigEntry, err := r.GetAcrCredentials(container.Image)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch acr credentials: %w", err)
		}

		sec := []corev1.Secret{ //{
			*dockerCfgSecretType.Create(container.Namespace, "secret", registry, authn.AuthConfig{
				Username: dockerConfigEntry.Username, Password: dockerConfigEntry.Password,
			}),
		}
		*authChain, err = k8schain.NewFromPullSecrets(
			ctx,
			sec,
		)
		if err != nil {
			return nil, err
		}

	default:
		klog.InfoS("using imagePullSecrets for registry authentication", "config.authType", authType)
		*authChain, err = k8schain.New(
			ctx,
			client,
			k8schain.Options{
				Namespace:          container.Namespace,
				ServiceAccountName: container.ServiceAccountName,
				ImagePullSecrets:   container.ImagePullSecrets,
			},
		)
		if err != nil {
			return nil, err
		}
	}

	options := []remote.Option{
		remote.WithAuthFromKeychain(*authChain),
	}

	if opt.SkipVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint:gosec
		}
		options = append(options, remote.WithTransport(tr))
	}
	return options, err
}

// getImageConfig download image blob from registry
func getImageConfig(container containerInfo, options []remote.Option) (*v1.Config, error) {
	ref, err := name.ParseReference(container.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	descriptor, err := remote.Get(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch image descriptor: %w", err)
	}

	image, err := descriptor.Image()
	if err != nil {
		return nil, fmt.Errorf("cannot convert image descriptor to v1.Image: %w", err)
	}

	configFile, err := image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("cannot extract config file of image: %w", err)
	}

	return &configFile.Config, nil
}

// containerInfo keeps information retrieved from POD based container definition
type containerInfo struct {
	Namespace          string
	ImagePullSecrets   []string
	ServiceAccountName string
	Image              string
}
