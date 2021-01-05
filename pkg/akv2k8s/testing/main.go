package testing

import (
	"os"
	"testing"
)

// EnsureIntegrationEnvironment will check env vars needed by integration tests
func EnsureIntegrationEnvironment(t *testing.T) {
	if os.Getenv("AKV2K8S_CLIENT_ID") == "" {
		t.Skip("Skipping integration test - no credentials")
	}

	os.Setenv("AZURE_CLIENT_ID", os.Getenv("AKV2K8S_CLIENT_ID"))
	os.Setenv("AZURE_CLIENT_SECRET", os.Getenv("AKV2K8S_CLIENT_SECRET"))
	os.Setenv("AZURE_TENANT_ID", os.Getenv("AKV2K8S_CLIENT_TENANT_ID"))
	os.Setenv("AZURE_SUBSCRIPTION_ID", os.Getenv("AKV2K8S_AZURE_SUBSCRIPTION_ID"))
}
