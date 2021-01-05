# Changelog for Version 1.1

## Version 1.1.1

The most notable changes in this release are:

* a complete rewrite of how Azure Key Vault authentication is handled and secured in Env-Injector
* a new Helm chart `akv2k8s` containing both the Controller and Env-Injector

### General

#### Features
* Support for Azure Managed Identities (MSI) when authenticating with Azure Key Vault
* Support fmt and json log formats - fmt is default
* Support other cloud types than Public Cloud (`AZURECHINACLOUD`, `AZUREGERMANCLOUD` and `AZUREUSGOVERNMENTCLOUD`)

#### Other 
* AzureKeyVaultSecret CRD version changed from `apiVersion: spv.no/v1alpha1` to `apiVersion: spv.no/v1` - still backward compatible with previous versions
* Kubernetes >= v0.17.4

### Env-Injector

#### Features
* Basic support for Prometheus metrics
* Use remote inspection, instead of docker pull, to find Docker image cmd or entrypoint
* As part of the Auth service, introduced a ca-bundle-controller that will sync akv2k8s ca-cert to every namespace enabled with env-injection
* Support for SHA Docker image notation 

#### Bug Fixes

* Provide Auth endpoint as a better and more secure alternative to storing credentials in a volume attached to a Pod - fixes issue #25 (and #42 #40 #39 and more) for getting oauth tokens to authenticate with Azure Key Vault
* Fix #69 - handle containers with no explicit cmd

### Controller

#### Features
* Add chainOrder option to ensure server certificate is first in chain (thanks to @david.mansson)

#### Bug Fixes
* #104 - pass on labels and annotations from AzureKeyVaultSecret to Kubernetes Secret

### Docs

* Updated tutorials
* Show multiple versions (currently 1.0 and 1.1) - where 1.1 is now default
* Updated authentication docs to reflect changes in 1.1

### Helm Charts

* Introduced a new Helm chart (`akv2k8s`) that contains both the Controller and Env-Injector in one chart AND uses Helm 3
* Removed CRDs from old charts (`azure-key-vault-controller` and `azure-key-vault-env-injector`)
* Updated installation instructions for why and how to manually install CRDs
* Fixed issue #55 where auth with ACR was not working
* Support log format fmt and json
* New charts have major changes in values - make sure to check yours match

### Chart and Image versions

| Type    |           Component                                   |                Version         |         
| ------- | ---------------------------------- | -----------------------------|
| Helm Chart | [akv2k8s](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/akv2k8s) | 1.1.24 |
| Helm Chart | [azure-key-vault-controller](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller) | 1.1.3 |
| Helm Chart | [azure-key-vault-env-injector](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector) | 1.1.18 |
| Docker Image | spvest/azure-keyvault-controller | 1.1.0 |
| Docker Image | spvest/azure-keyvault-webhook | 1.1.10 |
| Docker Image | spvest/azure-keyvault-env  | 1.1.1 |
| Docker Image | spvest/ca-bundle-controller | 1.1.0 |