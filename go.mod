module github.com/SparebankenVest/azure-key-vault-to-kubernetes

go 1.15

require (
	emperror.dev/errors v0.8.0
	github.com/Azure/aad-pod-identity v1.6.3
	github.com/Azure/azure-sdk-for-go v43.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.4
	github.com/Azure/go-autorest/autorest/adal v0.9.5
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/appscode/go v0.0.0-20191119085241-0887d8ec2ecc
	github.com/appscode/jsonpatch v0.0.0-20180911074601-5af499cf01c8 // indirect
	github.com/docker/docker v1.4.2-0.20190924003213-a8608b5b67c7
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/google/go-cmp v0.5.2
	github.com/google/go-containerregistry v0.4.0
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20210113221012-4eb508cda163
	github.com/gorilla/mux v1.7.4
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/opencontainers/image-spec v1.0.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.8.0
	github.com/sirupsen/logrus v1.6.0
	github.com/slok/kubewebhook v0.11.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/uber-go/atomic v1.4.0 // indirect
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	gopkg.in/yaml.v2 v2.4.0
	istio.io/pkg v0.0.0-20210201164122-c885290aa5be
	k8s.io/api v0.19.7
	k8s.io/apimachinery v0.19.7
	k8s.io/client-go v0.19.7
	k8s.io/code-generator v0.20.1 // indirect
	k8s.io/component-base v0.19.7
	k8s.io/klog/v2 v2.5.0
	kmodules.xyz/client-go v0.0.0-20200521013203-6fe0a448d053
	sigs.k8s.io/yaml v1.2.0
)
