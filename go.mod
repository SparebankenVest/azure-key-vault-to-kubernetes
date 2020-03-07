module github.com/SparebankenVest/azure-key-vault-to-kubernetes

go 1.13

require (
	github.com/Azure/azure-sdk-for-go v24.1.0+incompatible
	github.com/Azure/go-autorest/autorest v0.10.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/prometheus/client_golang v1.1.0
	github.com/sirupsen/logrus v1.4.2
	github.com/slok/kubewebhook v0.4.0
	github.com/spf13/viper v1.4.0
	golang.org/x/crypto v0.0.0-20191206172530-e9b2fee46413
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.0.0-20191004102255-dacd7df5a50b
	k8s.io/apimachinery v0.0.0-20191004074956-01f8b7d1121a
	k8s.io/client-go v0.0.0-20191004102537-eb5b9a8cfde7
	k8s.io/kube-openapi v0.0.0-20200204173128-addea2498afe // indirect
	k8s.io/kubernetes v1.13.11
)
