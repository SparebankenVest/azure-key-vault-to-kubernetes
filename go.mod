module github.com/SparebankenVest/azure-key-vault-to-kubernetes

go 1.13

require (
	github.com/Azure/azure-sdk-for-go v40.5.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.4
	github.com/Azure/go-autorest/autorest/adal v0.9.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/containers/image/v5 v5.3.0
	github.com/ghodss/yaml v1.0.0
	github.com/gorilla/mux v1.7.4
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/prometheus/client_golang v1.1.0
	github.com/sirupsen/logrus v1.4.2
	github.com/slok/kubewebhook v0.4.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.4.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gonum.org/v1/gonum v0.8.1 // indirect
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.15.11
	k8s.io/apimachinery v0.15.11
	k8s.io/client-go v0.15.11
	k8s.io/legacy-cloud-providers v0.15.11
	sigs.k8s.io/yaml v1.2.0
)
