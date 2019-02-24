# Azure Key Vault Controller

This chart will install a Kubernetes controller that uses information from `AzureKeyVaultSecret` resources to download secrets from Azure Key Vault and create them as Kubernetes native `Secret` resources.

This chart is a subchart of [`azure-key-vault-to-kubernetes`](../azure-key-vault-to-kubernetes) which allows a more secure handling of Azure Key Vault secrets, by transparantly injecting them into containers. 

For more information see the main GitHub repository at [https://github.com/SparebankenVest/azure-key-vault-to-kubernetes](https://github.com/SparebankenVest/azure-key-vault-to-kubernetes).

## Installing the Chart

```bash
$ helm repo add spv-charts http://charts.spv.no
$ helm repo update
```

```bash
$ helm install spv-charts/azure-key-vault-controller
```

## Configuration

The following table lists configurable parameters of the azure-key-vault-controller chart and their default values.

|               Parameter             |                Description                   |                  Default                 |
| ----------------------------------- | -------------------------------------------- | -----------------------------------------|
|image.repository                     |image repo that contains the controller image | spvest/azure-keyvault-controller         |
|image.tag                            |image tag|0.1.0-alpha.5|
|keyVault.secret.name                 |name of kubernetes secret containing azure key vault credentials | azure-keyvault-credentials|
|keyVault.secret.tenantKey            |key name used for tenant inside kubernetes secret | tenant-id |
|keyVault.secret.clientIdKey          |key name used for clientId inside kubernetes secret | client-id |
|keyVault.secret.clientSecretKey      |key name used for clientSecret inside kubernetes secret | client-secret |
|keyVault.polling.normalInterval      |interval to wait before polling azure key vault for secret updates | 1m |
|keyVault.polling.failureInterval     |interval to wait when polling has failed `failureAttempts` before polling azure key vault for secret updates | 5m |
|keyVault.polling.failureAttempts     |number of times to allow secret updates to fail before applying `failureInterval` | 5 |
|logLevel                             | log level | info |