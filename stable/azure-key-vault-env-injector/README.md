# Azure Key Vault Env Injector

**This helm chart is still in Alpha and not yet ready for public consumption**

This chart will install a Custom Resource Definition (`AzureKeyVaultEnvSecret`) and a mutating admission webhook, that together enable transparent injection of Azure Key Vault secrets to containers as environment variables.

For more information see the main GitHub repository at https://github.com/SparebankenVest/azure-key-vault-to-kubernetes.

## Installing the Chart

```bash
$ helm repo add spv-charts http://charts.spvapi.no
$ helm repo update
```

```bash
$ helm install spv-charts/azure-key-vault-env-injector
```

## Configuration

The following tables lists configurable parameters of the azure-key-vault-env-injector chart and their default values.

|               Parameter             |                Description                  |                  Default                 |
| ----------------------------------- | ------------------------------------------- | -----------------------------------------|
|affinity                             |affinities to use                            |{}                                        |
|debug                                |debug logs for webhook                       |false                                     |
|image.pullPolicy                     |image pull policy                            |IfNotPresent                              |
|image.repository                     |image repo that contains the admission server|banzaicloud/vault-secrets-webhook         |
|image.tag                            |image tag                                    |latest                                    |
|nodeSelector                         |node selector to use                         |{}                                        |
|replicaCount                         |number of replicas                           |1                                         |
|resources                            |resources to request                         |{}                                        |
|service.externalPort                 |webhook service external port                |443                                       |
|service.internalPort                 |webhook service external port                |443                                       |
|service.name                         |webhook service name                         |vault-secrets-webhook                     |
|service.type                         |webhook service type                         |ClusterIP                                 |
|tolerations                          |tolerations to add                           |[]                                        |
