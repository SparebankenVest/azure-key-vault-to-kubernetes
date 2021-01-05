# Changelog for Version 1.0

## Version 1.0.2

Unfortunately we had to patch away the functionality in the env-injector for removing sensitive files. The previous implementation caused issues if a pod crashed after initial startup and was unable to recover (because the filles needed where no longer present). We are currently working on a better and more secure solution, which will be released as soon as we can.

### Chart and Image versions

We have bumped all versions, but only the env-injector has changed.

| Type         |           Component                |              Version         |         
| ------------ | ---------------------------------- | -----------------------------|
| Helm Chart   | [azure-key-vault-controller](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller) | 1.0.2 |
| Helm Chart   | [azure-key-vault-env-injector](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector) | 1.0.2 |
| Docker Image | spvest/azure-keyvault-controller | 1.0.2 |
| Docker Image | spvest/azure-keyvault-webhook | 1.0.2 |
| Docker Image | spvest/azure-keyvault-env  | 1.0.2 |


## Version 1.0.0

### Added

* [docs] New documentation portal at https://akv2k8s.io
* [env-injector] Improved logging
* [env-injector] Prometheus metrics
* [env-injector] Retry (up to 3 times) if fail to access AzureKeyVaultSecret on first try (ref: #34 )
* [env-injector] Support getting raw certificate (`?raw`)
* [controller & env-injector] Support all Azure environments (public, china, german, us-gov) - thanks @mayong43111 ❗️ 

### Changed

* [env-injector] Custom authentication
* [env-injector] Delete sensitive files
* [env-injector] Not map host volume for azure.json when using custom auth
* [env-injector] Canonical names for Docker images
* [controller] Use optional param for --cloudconfig (was hardcoded) - thanks @reiniertimmer ❗️  
