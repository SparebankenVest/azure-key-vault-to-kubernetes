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

package credentialprovider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/go-autorest/autorest/azure"
	myazure "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
	k8sCredentialProvider "github.com/vdemeester/k8s-pkg-credentialprovider"
	"k8s.io/klog/v2"
)

var (
	acrRE = regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)
)

func NewAcrDockerProvider(provider CredentialProvider) k8sCredentialProvider.DockerConfigProvider {
	return acrDockerProvider{
		internalProvider: provider,
	}
}

// acrDockerProvider handles docker credentials for ACR
type acrDockerProvider struct {
	internalProvider CredentialProvider
}

func (acr acrDockerProvider) Enabled() bool {
	return true
}

func (acr acrDockerProvider) Provide(image string) k8sCredentialProvider.DockerConfig {
	cfg := k8sCredentialProvider.DockerConfig{}

	creds, err := acr.internalProvider.GetAcrCredentials(image)
	if err != nil {
		klog.ErrorS(err, "failed to get acr credentials")
		return cfg
	}

	return k8sCredentialProvider.DockerConfig{
		"*.azurecr.*": creds,
	}
}

// GetAcrCredentials will get Docker credentials for Azure Container Registry
// It will either get a exact match to the login server for the image (eg xxx.azureacr.io) or
// get credentials for a wildcard match (eg *.azureacr.io* or *.azureacr.cn*)
func (c CloudConfigCredentialProvider) GetAcrCredentials(image string) (k8sCredentialProvider.DockerConfigEntry, error) {
	cred := k8sCredentialProvider.DockerConfigEntry{
		Username: "",
		Password: "",
	}

	if c.config.UseManagedIdentityExtension {
		klog.V(4).Info("using managed identity for acr credentials")
		loginServer := parseACRLoginServerFromImage(image, c.environment)

		if loginServer == "" {
			klog.V(4).InfoS("image is not from ACR, skip MSI authentication", "image", image)
		} else {
			token, err := getServicePrincipalTokenFromCloudConfig(c.config, c.environment, c.environment.ServiceManagementEndpoint)
			if err != nil {
				return cred, err
			}
			if managedCred, err := getACRDockerEntryFromARMToken(c.config.TenantID, *c.environment, myazure.NewLegacyTokenCredentialAdal(token), loginServer); err == nil {
				klog.V(4).InfoS("found acr gredentials", "url", loginServer)
				return managedCred, nil
			}
		}
	} else {
		return k8sCredentialProvider.DockerConfigEntry{
			Username: c.config.AADClientID,
			Password: c.config.AADClientSecret,
		}, nil
	}

	return cred, nil
}

func (c EnvironmentCredentialProvider) GetAcrCredentials(image string) (k8sCredentialProvider.DockerConfigEntry, error) {
	cred := k8sCredentialProvider.DockerConfigEntry{
		Username: "",
		Password: "",
	}

	creds, err := getCredentials(c.envSettings, c.envSettings.Environment.ServiceManagementEndpoint)
	if err != nil {
		return cred, err
	}

	loginServer := parseACRLoginServerFromImage(image, &c.envSettings.Environment)

	if loginServer == "" {
		klog.V(4).InfoS("image is not from acr, skip msi auth", "image", image)
	} else {
		managedCred, err := getACRDockerEntryFromARMToken(creds.tenantID, c.envSettings.Environment, myazure.NewLegacyTokenCredentialAdal(creds.token), loginServer)
		if err != nil {
			return cred, err
		}

		return managedCred, nil
	}
	return cred, nil
}

func (c AzidentityCredentialProvider) GetAcrCredentials(image string) (k8sCredentialProvider.DockerConfigEntry, error) {
	cred := k8sCredentialProvider.DockerConfigEntry{
		Username: "",
		Password: "",
	}

	creds, err := getCredentialsAzidentity()
	if err != nil {
		return cred, err
	}

	loginServer := parseACRLoginServerFromImage(image, &c.envSettings.Environment)

	if loginServer == "" {
		klog.V(4).InfoS("image is not from acr, skip msi auth", "image", image)
	} else {
		managedCred, err := getACRDockerEntryFromARMToken("", c.envSettings.Environment, creds, loginServer)
		if err != nil {
			return cred, err
		}

		return managedCred, nil
	}
	return cred, nil
}

// IsAcrRegistry checks if an image blongs to a ACR registry
func (c CloudConfigCredentialProvider) IsAcrRegistry(image string) bool {
	return parseACRLoginServerFromImage(image, c.environment) != ""
}

// IsAcrRegistry checks if an image blongs to a ACR registry
func (c EnvironmentCredentialProvider) IsAcrRegistry(image string) bool {
	return parseACRLoginServerFromImage(image, &c.envSettings.Environment) != ""
}

func getACRDockerEntryFromARMToken(tenantID string, env azure.Environment, token myazure.LegacyTokenCredential, loginServer string) (k8sCredentialProvider.DockerConfigEntry, error) {
	// Run EnsureFresh to make sure the token is valid and does not expire
	// if err := token.EnsureFresh(); err != nil {
	// 	return nil, fmt.Errorf("Failed to ensure fresh service principal token: %v", err)
	// }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cred := k8sCredentialProvider.DockerConfigEntry{
		Username: "",
		Password: "",
	}

	result, err := token.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{env.ServiceManagementEndpoint}})

	if err != nil {
		return cred, fmt.Errorf("failed to refresh token using resource %s, error: %+v", env.ServiceManagementEndpoint, err)
	}

	klog.V(4).InfoS("discovering auth redirects", "url", loginServer)
	directive, err := receiveChallengeFromLoginServer(loginServer)
	if err != nil {
		return cred, fmt.Errorf("failed to receive challenge: %s", err)
	}

	klog.V(4).Info("exchanging an acr refresh_token")
	registryRefreshToken, err := performTokenExchange(loginServer, directive, tenantID, result.Token)
	if err != nil {
		return cred, fmt.Errorf("failed to perform token exchange: %s", err)
	}

	klog.V(4).InfoS("adding ACR docker config entry", "url", loginServer)
	return k8sCredentialProvider.DockerConfigEntry{
		Username: dockerTokenLoginUsernameGUID,
		Password: registryRefreshToken,
	}, nil
}

// parseACRLoginServerFromImage takes image as parameter and returns login server of it.
// Parameter `image` is expected in following format: foo.azurecr.io/bar/imageName:version
// If the provided image is not an acr image, this function will return an empty string.
func parseACRLoginServerFromImage(image string, env *azure.Environment) string {
	match := acrRE.FindAllString(image, -1)
	if len(match) == 1 {
		return match[0]
	}

	// handle the custom cloud case
	if env != nil {
		cloudAcrSuffix := env.ContainerRegistryDNSSuffix
		cloudAcrSuffixLength := len(cloudAcrSuffix)
		if cloudAcrSuffixLength > 0 {
			customAcrSuffixIndex := strings.Index(image, cloudAcrSuffix)
			if customAcrSuffixIndex != -1 {
				endIndex := customAcrSuffixIndex + cloudAcrSuffixLength
				return image[0:endIndex]
			}
		}
	}

	return ""
}
