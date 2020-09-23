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

package credentialprovider

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	docker "github.com/containers/image/v5/types"

	azureAuth "github.com/Azure/go-autorest/autorest/azure/auth"
	log "github.com/sirupsen/logrus"
	"k8s.io/legacy-cloud-providers/azure/auth"
)

var (
	containerRegistryUrls = []string{"*.azurecr.io", "*.azurecr.cn", "*.azurecr.de", "*.azurecr.us"}
	acrRE                 = regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)
)

// DockerConfig contains credentials used to access Docker regestries
type DockerConfig map[string]docker.DockerAuthConfig

// AcrCloudConfigProvider provides credentials for Azure
type AcrCloudConfigProvider struct {
	config                *auth.AzureAuthConfig
	environment           *azure.Environment
	servicePrincipalToken *adal.ServicePrincipalToken
}

// NewAcrCredentialsFromCloudConfig parses the specified configFile and returns a DockerConfigProvider
func NewAcrCredentialsFromCloudConfig(configReader io.Reader) (*AcrCloudConfigProvider, error) {
	authSettings, err := azureAuth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed getting settings from environment, err: %+v", err)
	}

	token, config, err := getServicePrincipalTokenFromCloudConfig(configReader, authSettings.Environment, authSettings.Environment.ServiceManagementEndpoint)

	if err != nil {
		return nil, err
	}

	return &AcrCloudConfigProvider{
		config:                config,
		environment:           &authSettings.Environment,
		servicePrincipalToken: token,
	}, nil
}

// GetAcrCredentials will get Docker credentials for Azure Container Registry
func (c AcrCloudConfigProvider) GetAcrCredentials(image string) (DockerConfig, error) {
	cfg := DockerConfig{}

	if c.config.UseManagedIdentityExtension {
		log.Debug("using managed identity for acr credentials")
		if loginServer := parseACRLoginServerFromImage(image, c.environment); loginServer == "" {
			log.Debugf("image(%s) is not from ACR, skip MSI authentication", image)
		} else {
			if cred, err := getACRDockerEntryFromARMToken(c.config, *c.environment, c.servicePrincipalToken, loginServer); err == nil {
				cfg[loginServer] = *cred
			}
		}
	} else {
		// Add our entry for each of the supported container registry URLs
		for _, url := range containerRegistryUrls {
			cred := &docker.DockerAuthConfig{
				Username: c.config.AADClientID,
				Password: c.config.AADClientSecret,
			}
			cfg[url] = *cred
		}

		// Handle the custom cloud case
		// In clouds where ACR is not yet deployed, the string will be empty
		if c.environment != nil && strings.Contains(c.environment.ContainerRegistryDNSSuffix, ".azurecr.") {
			customAcrSuffix := "*" + c.environment.ContainerRegistryDNSSuffix
			hasBeenAdded := false
			for _, url := range containerRegistryUrls {
				if strings.EqualFold(url, customAcrSuffix) {
					hasBeenAdded = true
					break
				}
			}

			if !hasBeenAdded {
				cred := &docker.DockerAuthConfig{
					Username: c.config.AADClientID,
					Password: c.config.AADClientSecret,
				}
				cfg[customAcrSuffix] = *cred
			}
		}
	}

	// add ACR anonymous repo support: use empty username and password for anonymous access
	cfg["*.azurecr.*"] = docker.DockerAuthConfig{
		Username: "",
		Password: "",
	}
	return cfg, nil
}

func getACRDockerEntryFromARMToken(config *auth.AzureAuthConfig, env azure.Environment, token *adal.ServicePrincipalToken, loginServer string) (*docker.DockerAuthConfig, error) {
	// Run EnsureFresh to make sure the token is valid and does not expire
	// if err := token.EnsureFresh(); err != nil {
	// 	return nil, fmt.Errorf("Failed to ensure fresh service principal token: %v", err)
	// }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := token.RefreshExchangeWithContext(ctx, env.ServiceManagementEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token using resource %s, error: %+v", env.ServiceManagementEndpoint, err)
	}

	armAccessToken := token.OAuthToken()

	log.Debugf("discovering auth redirects for: %s", loginServer)
	directive, err := receiveChallengeFromLoginServer(loginServer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive challenge: %s", err)
	}

	log.Debug("exchanging an acr refresh_token")
	registryRefreshToken, err := performTokenExchange(loginServer, directive, config.TenantID, armAccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform token exchange: %s", err)
	}

	log.Debugf("adding ACR docker config entry for: %s", loginServer)
	return &docker.DockerAuthConfig{
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
