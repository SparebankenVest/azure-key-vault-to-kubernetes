/*
Copyright Sparebanken Vest

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"os"
	"testing"
)

// func TestAuthDefault(t *testing.T) {
// 	creds, err := NewAzureKeyVaultCredentialsFromEnvironment()
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	_, err = creds.
// 	if err == nil {
// 		t.Fail()
// 	}
// }

func TestChinaCloud(t *testing.T) {
	os.Setenv("AZURE_ENVIRONMENT", "AzureChinaCloud")

	creds, err := NewAzureKeyVaultCredentialsFromEnvironment()
	if err != nil {
		t.Error(err)
	}

	if creds.Endpoint("test") != "https://test.vault.azure.cn/" {
		t.Errorf("Endpoint incorrect. Exprected '%s', but got '%s'", "https://test.vault.azure.cn/", creds.Endpoint("test"))
	}
}
