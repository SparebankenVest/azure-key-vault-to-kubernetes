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
	"fmt"

	akvs "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/k8s/apis/azurekeyvault/v2beta1"
)

// CreateTransformator creates a new Transformator ready to run transformation handlers
func CreateTransformator(spec *akvs.AzureKeyVaultOutput) (*Transformator, error) {
	var transforms []TransformationHandler

	if spec == nil {
		return &Transformator{
			transHandlers: transforms,
		}, nil
	}

	for _, transform := range spec.Transforms {
		switch transform {
		case "trim":
			transforms = append(transforms, &TrimHandler{})
		case "base64encode":
			transforms = append(transforms, &Base64EncodeHandler{})
		case "base64decode":
			transforms = append(transforms, &Base64DecodeHandler{})
		default:
			return nil, fmt.Errorf("transform type '%s' not currently supported", transform)
		}
	}

	return &Transformator{
		transHandlers: transforms,
	}, nil
}

// Transformator
type Transformator struct {
	transHandlers []TransformationHandler
}

func (t *Transformator) Transform(secret string) (string, error) {
	var err error
	for _, handler := range t.transHandlers {
		if secret, err = handler.Handle(secret); err != nil {
			return "", err
		}
	}
	return secret, nil
}
