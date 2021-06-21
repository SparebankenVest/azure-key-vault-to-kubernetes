module github.com/SparebankenVest/azure-key-vault-to-kubernetes

go 1.15

require (
	emperror.dev/errors v0.8.0
	github.com/Azure/aad-pod-identity v1.6.3
	github.com/Azure/azure-sdk-for-go v42.3.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.19
	github.com/Azure/go-autorest/autorest/adal v0.9.14
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/appscode/go v0.0.0-20191119085241-0887d8ec2ecc
	github.com/google/go-cmp v0.5.5
	github.com/google/go-containerregistry v0.4.0
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20210113221012-4eb508cda163
	github.com/gorilla/mux v1.8.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.0
	github.com/slok/kubewebhook v0.11.0
	github.com/spf13/viper v1.8.0
	github.com/vdemeester/k8s-pkg-credentialprovider v1.18.1-0.20201019120933-f1d16962a4db
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.20.2
	k8s.io/component-base v0.20.2
	k8s.io/klog/v2 v2.9.0
	kmodules.xyz/client-go v0.0.0-20200521013203-6fe0a448d053
	sigs.k8s.io/controller-runtime v0.8.2
	sigs.k8s.io/yaml v1.2.0
)
