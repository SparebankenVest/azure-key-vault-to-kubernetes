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

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	dockerTypes "github.com/docker/docker/api/types"
	log "github.com/sirupsen/logrus"
)

var (
	containerRegistryUrls = []string{"*.azurecr.io", "*.azurecr.cn", "*.azurecr.de", "*.azurecr.us"}
	acrRE                 = regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)
)

// GetAcrCredentials will get Docker credentials for Azure Container Registry
// It will either get a exact match to the login server for the image (eg xxx.azureacr.io) or
// get credentials for a wildcard match (eg *.azureacr.io* or *.azureacr.cn*)
func (c CloudConfigCredentialProvider) GetAcrCredentials(image string) (*dockerTypes.AuthConfig, error) {
	cred := &dockerTypes.AuthConfig{
		Username: "",
		Password: "",
	}

	if c.config.UseManagedIdentityExtension {
		log.Debug("using managed identity for acr credentials")
		if loginServer := parseACRLoginServerFromImage(image, c.environment); loginServer == "" {
			log.Debugf("image(%s) is not from ACR, skip MSI authentication", image)
		} else {
			token, err := getServicePrincipalTokenFromCloudConfig(c.config, c.environment, c.environment.ServiceManagementEndpoint)
			if err != nil {
				return nil, err
			}

			if managedCred, err := getACRDockerEntryFromARMToken(c.config, *c.environment, token, loginServer); err == nil {
				log.Debugf("found acr gredentials for %s", loginServer)
				return managedCred, nil
			}
		}
	} else {
		return &dockerTypes.AuthConfig{
			Username: c.config.AADClientID,
			Password: c.config.AADClientSecret,
		}, nil
	}

	return cred, nil
}

// IsAcrRegistry checks if an image blongs to a ACR registry
func (c CloudConfigCredentialProvider) IsAcrRegistry(image string) bool {
	return parseACRLoginServerFromImage(image, c.environment) != ""
}

func getACRDockerEntryFromARMToken(config *AzureCloudConfig, env azure.Environment, token *adal.ServicePrincipalToken, loginServer string) (*dockerTypes.AuthConfig, error) {
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
	return &dockerTypes.AuthConfig{
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
