package client

import (
	"fmt"
	"os"
	"strings"
)

const (
	EnvironmentName = "AZURE_ENVIRONMENT"
)

var settings = map[string]AzureEnvironmentSetting{
	"AZURECHINACLOUD":        ChinaCloud,
	"AZUREGERMANCLOUD":       GermanCloud,
	"AZUREPUBLICCLOUD":       PublicCloud,
	"AZUREUSGOVERNMENTCLOUD": USGovernmentCloud,
}

// AzureEnvironmentSetting represents a set of endpoints for each of Azure's Clouds.
type AzureEnvironmentSetting struct {
	Name                     string `json:"name"`
	AzureKeyVaultURI         string `json:"AzureKeyVault URI"`
	AzureKeyVaultResourceURI string `json:"AzureKeyVaultResourceURI"`
}

var (
	// PublicCloud is the default public Azure cloud environment
	PublicCloud = AzureEnvironmentSetting{
		Name:                     "AzurePublicCloud",
		AzureKeyVaultURI:         "https://vault.azure.net",
		AzureKeyVaultResourceURI: "https://%s.vault.azure.net",
	}

	// USGovernmentCloud is the cloud environment for the US Government
	USGovernmentCloud = AzureEnvironmentSetting{
		Name:                     "AzureUSGovernmentCloud",
		AzureKeyVaultURI:         "https://vault.usgovcloudapi.net",
		AzureKeyVaultResourceURI: "https://%s.vault.usgovcloudapi.net",
	}

	// ChinaCloud is the cloud environment operated in China
	ChinaCloud = AzureEnvironmentSetting{
		Name:                     "AzureChinaCloud",
		AzureKeyVaultURI:         "https://vault.azure.cn",
		AzureKeyVaultResourceURI: "https://%s.vault.azure.cn",
	}

	// GermanCloud is the cloud environment operated in Germany
	GermanCloud = AzureEnvironmentSetting{
		Name:                     "AzureGermanCloud",
		AzureKeyVaultURI:         "https://vault.microsoftazure.de",
		AzureKeyVaultResourceURI: "https://%s.vault.microsoftazure.de",
	}
)

func GetAzureEnvironmentSetting() (AzureEnvironmentSetting, error) {

	if v := os.Getenv(EnvironmentName); v == "" {
		return settings["AZUREPUBLICCLOUD"], nil
	} else {
		return GetAzureEnvironmentSettingFromName(v)
	}
}

// EnvironmentFromName returns an Environment based on the common name specified.
func GetAzureEnvironmentSettingFromName(name string) (AzureEnvironmentSetting, error) {

	name = strings.ToUpper(name)
	env, ok := settings[name]
	if !ok {
		return env, fmt.Errorf("autorest/azure: There is no cloud environment matching the name %q", name)
	}

	return env, nil
}
