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

package transformers

import (
	"testing"

	akvsv1 "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v1"
)

const (
	testString        string = "  alsdjfl ljasfk   "
	testBase64String  string = "ICBhbHNkamZsIGxqYXNmayAgIA=="
	testStringTrimmed string = "alsdjfl ljasfk"
)

func TestTransformWithTrim(t *testing.T) {
	secretSpec := akvsv1.AzureKeyVaultOutput{
		Transforms: []string{"trim"},
	}

	transformator, err := CreateTransformator(&secretSpec)
	if err != nil {
		t.Error(err)
	}

	newSecret, err := transformator.Transform(testString)

	if newSecret != testStringTrimmed {
		t.Error("Secret not properly trimmed with white space")
	}
}

func TestTransformWithBase64Decode(t *testing.T) {
	secretSpec := akvsv1.AzureKeyVaultOutput{
		Transforms: []string{"base64decode"},
	}

	transformator, err := CreateTransformator(&secretSpec)
	if err != nil {
		t.Error(err)
	}

	newSecret, err := transformator.Transform(testBase64String)

	if newSecret != testString {
		t.Errorf("Actual   :%s", newSecret)
		t.Errorf("Expected :%s", testString)
	}
}

func TestTransformWithBase64Encode(t *testing.T) {
	secretSpec := akvsv1.AzureKeyVaultOutput{
		Transforms: []string{"base64encode"},
	}

	transformator, err := CreateTransformator(&secretSpec)
	if err != nil {
		t.Error(err)
	}

	newSecret, err := transformator.Transform(testString)

	if newSecret != testBase64String {
		t.Errorf("Actual   :%s", newSecret)
		t.Errorf("Expected :%s", testString)
	}
}

func TestTransformWithAll(t *testing.T) {
	secretSpec := akvsv1.AzureKeyVaultOutput{
		Transforms: []string{"base64encode", "base64decode", "trim"},
	}

	transformator, err := CreateTransformator(&secretSpec)
	if err != nil {
		t.Error(err)
	}

	newSecret, err := transformator.Transform(testString)

	if newSecret != testStringTrimmed {
		t.Errorf("Actual   :%s", newSecret)
		t.Errorf("Expected :%s", testString)
	}
}

func TestTransformUnknown(t *testing.T) {
	secretSpec := akvsv1.AzureKeyVaultOutput{
		Transforms: []string{"nonexistant"},
	}

	_, err := CreateTransformator(&secretSpec)
	if err == nil {
		t.Error("Unknown transformer should throw")
	}
}

func TestTransformWithNilOutputSpec(t *testing.T) {
	transformator, err := CreateTransformator(nil)
	if err != nil {
		t.Error("Transform should handle nil Output spec")
	}

	newSecret, err := transformator.Transform(testString)
	if newSecret != testString {
		t.Errorf("Transform should work without any transformers")
	}

}
