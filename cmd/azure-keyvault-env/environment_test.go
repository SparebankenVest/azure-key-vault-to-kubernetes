package main

import (
	"testing"
)

func TestParseEnvVars(t *testing.T) {
	envVars := []string{
		"TEST_CERTIFICATE=certificate-inject@azurekeyvault?tls.crt",
		"TEST_KEY=key-inject@azurekeyvault?tls.key",
		"TEST_EXAMPLE=example-inject@azurekeyvault?example",
		"TEST_EMPTY=empty-inject@azurekeyvault?",
		"TEST_SECRET=secret-inject@azurekeyvault",
		"TEST_SECRET_REGULAR=secret-no-inject",
	}
	expectedResult := map[string]EnvSecret{
		"TEST_CERTIFICATE": {
			akvsName: "certificate-inject",
			query:    "tls.crt",
			index:    0,
		},
		"TEST_KEY": {
			akvsName: "key-inject",
			query:    "tls.key",
			index:    1,
		},
		"TEST_EXAMPLE": {
			akvsName: "example-inject",
			query:    "example",
			index:    2,
		},
		"TEST_EMPTY": {
			akvsName: "empty-inject",
			query:    "",
			index:    3,
		},
		"TEST_SECRET": {
			akvsName: "secret-inject",
			query:    "",
			index:    4,
		},
	}

	result, err := parseEnvVars(envVars)
	if err != nil {
		t.Errorf("Expected no error, but got %s", err)
	}

	if len(result) != len(expectedResult) {
		t.Errorf("Expected length of result to be %d, but got %d", len(expectedResult), len(result))
	}

	for key, value := range result {
		expectedValue, exists := expectedResult[key]
		if !exists {
			t.Errorf("Expected result to contain key %s", key)
			continue
		}

		if value.akvsName != expectedValue.akvsName {
			t.Errorf("Expected akvsName for key %s to be %s, but got %s", key, expectedValue.akvsName, value.akvsName)
		}
		if value.query != expectedValue.query {
			t.Errorf("Expected query for key %s to be %s, but got %s", key, expectedValue.query, value.query)
		}
		if value.index != expectedValue.index {
			t.Errorf("Expected index for key %s to be %d, but got %d", key, expectedValue.index, value.index)
		}
	}
}
