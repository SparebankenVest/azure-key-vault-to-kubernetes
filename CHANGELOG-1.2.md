# Changelog for Version 1.2

*Note: Features and bug fixes are added here while working towards the 1.2 release*

## Version 1.2.0

The most notable changes in this release are:

* The Controller support sync to ConfigMap
* The Controller support several AKVS pointing to same Secret/ConfigMap

### General

#### Features
* 

#### Other 
* 

### Env-Injector

#### Features
* If Auth Service is enabled (default), the container being injected use mTls to authenticate with Env-Injector Auth Service, to get OAuth credentials for Azure Key Vault

#### Bug Fixes

* 

### Controller

#### Features
* Support sync to ConfigMap (requires AzureKeyVaultSecret `apiVersion: spv.no/v2alpha1`)

#### Bug Fixes
* 

#### Other
* The CA Bundle sync is removed, as this is now handled in the Env-Injector

### Docs

* 

### Helm Charts

* 

### Chart and Image versions

| Type    |           Component                                   |                Version         |         
| ------- | ---------------------------------- | -----------------------------|
| Helm Chart | [akv2k8s](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/akv2k8s) | 2.0.0 |
| Helm Chart | [azure-key-vault-controller](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller) | 1.2.0 |
| Helm Chart | [azure-key-vault-env-injector](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector) | 1.2.0 |
| Docker Image | spvest/azure-keyvault-controller | 1.2.0 |
| Docker Image | spvest/azure-keyvault-webhook | 1.2.0 |
| Docker Image | spvest/azure-keyvault-env  | 1.2.0 |
| Docker Image | spvest/ca-bundle-controller | 1.2.0 |