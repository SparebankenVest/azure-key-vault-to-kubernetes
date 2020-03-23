module github.com/SparebankenVest/azure-key-vault-to-kubernetes

go 1.13

require (
	github.com/Azure/azure-sdk-for-go v40.5.0+incompatible
	github.com/Azure/go-autorest/autorest v0.10.0
	github.com/Azure/go-autorest/autorest/adal v0.8.2
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/containers/image/v5 v5.3.0
	github.com/ghodss/yaml v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/prometheus/client_golang v1.1.0
	github.com/sirupsen/logrus v1.4.2
	github.com/slok/kubewebhook v0.4.0
	github.com/spf13/viper v1.4.0
	golang.org/x/crypto v0.0.0-20200214034016-1d94cc7ab1c6
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.0.0-20191004102255-dacd7df5a50b
	k8s.io/apimachinery v0.0.0-20191004074956-01f8b7d1121a
	k8s.io/client-go v0.0.0-20191004102537-eb5b9a8cfde7
	k8s.io/kube-openapi v0.0.0-20200204173128-addea2498afe // indirect
	k8s.io/kubernetes v1.13.11
)
