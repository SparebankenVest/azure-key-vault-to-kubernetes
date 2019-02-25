# Azure Key Vault for Kubernetes

**This helm chart is still in Alpha and not yet ready for public consumption**

This chart will install a Kubernetes controller to handle `AzureKeyValuSecret` resources and a mutating admission webhook, that transparantly injects Azure Key Vault secrets into containers.

For more information see the main GitHub repository at [https://github.com/SparebankenVest/azure-key-vault-to-kubernetes](https://github.com/SparebankenVest/azure-key-vault-to-kubernetes).

## Installing the Chart

```bash
$ helm repo add spv-charts http://charts.spvapi.no
$ helm repo update
```

```bash
$ helm install spv-charts/azure-key-vault-for-kubernetes
```

## Configuration

The following tables lists configurable parameters of the vault-secrets-webhook chart and their default values.

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
