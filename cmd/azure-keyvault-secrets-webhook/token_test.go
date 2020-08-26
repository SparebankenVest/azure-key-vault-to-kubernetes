package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
)

func TestMarshallToken(t *testing.T) {
	if os.Getenv("AKV2K8S_CLIENT_ID") == "" {
		t.Skip("Skipping integration test - no credentials")
	}

	os.Setenv("AZURE_CLIENT_ID", os.Getenv("AKV2K8S_CLIENT_ID"))
	os.Setenv("AZURE_CLIENT_SECRET", os.Getenv("AKV2K8S_CLIENT_SECRET"))
	os.Setenv("AZURE_TENANT_ID", os.Getenv("AKV2K8S_CLIENT_TENANT_ID"))

	creds, err := azure.NewFromEnvironment()
	if err != nil {
		t.Error(err)
	}

	data, err := json.Marshal(creds)
	if err != nil {
		t.Error(err)
	}

	var creds2 azure.OAuthCredentials
	err = json.Unmarshal(data, &creds2)
	if err != nil {
		t.Error(err)
	}
}
