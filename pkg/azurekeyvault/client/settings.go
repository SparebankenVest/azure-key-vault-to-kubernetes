package client

import (
	"fmt"
	"os"
	"strings"
)

const (
	EnvironmentName = "AZURE_ENVIRONMENT"
)

var settings = map[string]Setting{
	"AZURECHINACLOUD":        ChinaCloud,
	"AZUREGERMANCLOUD":       GermanCloud,
	"AZUREPUBLICCLOUD":       PublicCloud,
	"AZUREUSGOVERNMENTCLOUD": USGovernmentCloud,
}

// Environment represents a set of endpoints for each of Azure's Clouds.
type Setting struct {
	Name                     string `json:"name"`
	AzureKeyVaultURI         string `json:"AzureKeyVault URI"`
	AzureKeyVaultResourceURI string `json:"AzureKeyVaultResourceURI"`
}

var (
	// PublicCloud is the default public Azure cloud environment
	PublicCloud = Setting{
		Name:                     "AzurePublicCloud",
		AzureKeyVaultURI:         "https://vault.azure.net",
		AzureKeyVaultResourceURI: "https://%s.vault.azure.net",
	}

	// USGovernmentCloud is the cloud environment for the US Government
	USGovernmentCloud = Setting{
		Name:                     "AzureUSGovernmentCloud",
		AzureKeyVaultURI:         "https://vault.usgovcloudapi.net",
		AzureKeyVaultResourceURI: "https://%s.vault.usgovcloudapi.net",
	}

	// ChinaCloud is the cloud environment operated in China
	ChinaCloud = Setting{
		Name:                     "AzureChinaCloud",
		AzureKeyVaultURI:         "https://vault.azure.cn",
		AzureKeyVaultResourceURI: "https://%s.vault.azure.cn",
	}

	// GermanCloud is the cloud environment operated in Germany
	GermanCloud = Setting{
		Name:                     "AzureGermanCloud",
		AzureKeyVaultURI:         "https://vault.microsoftazure.de",
		AzureKeyVaultResourceURI: "https://%s.vault.microsoftazure.de",
	}
)

func GetSettingFromEnvironment() (Setting, error) {

	if v := os.Getenv(EnvironmentName); v == "" {
		return settings["AZUREPUBLICCLOUD"], nil
	} else {
		return SettingFromName(v)
	}
}

// EnvironmentFromName returns an Environment based on the common name specified.
func SettingFromName(name string) (Setting, error) {

	name = strings.ToUpper(name)
	env, ok := settings[name]
	if !ok {
		return env, fmt.Errorf("autorest/azure: There is no cloud environment matching the name %q", name)
	}

	return env, nil
}
