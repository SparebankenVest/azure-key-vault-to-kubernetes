package registry

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type secretType struct {
	name    corev1.SecretType
	key     string
	marshal func(registry string, auth authn.AuthConfig) []byte
}

func (s *secretType) Create(namespace, name string, registry string, auth authn.AuthConfig) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: s.name,
		Data: map[string][]byte{
			s.key: s.marshal(registry, auth),
		},
	}
}

var dockerCfgSecretType = secretType{
	name: corev1.SecretTypeDockercfg,
	key:  corev1.DockerConfigKey,
	marshal: func(target string, auth authn.AuthConfig) []byte {
		return toJSON(map[string]authn.AuthConfig{target: auth})
	},
}

func toJSON(obj any) []byte {
	bites, err := json.Marshal(obj)

	if err != nil {
		fmt.Errorf("unable to json marshal: %w", err)
	}
	return bites
}
