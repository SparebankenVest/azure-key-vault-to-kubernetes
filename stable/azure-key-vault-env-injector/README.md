---
title: "Env-Injector Helm Chart"
description: "Azure Key Vault Env-Injector reference"
---

This chart will install a Custom Resource Definition (`AzureKeyVaultEnvSecret`) and a mutating admission webhook, that together enable transparent injection of Azure Key Vault secrets to containers as environment variables.

For more information see the main GitHub repository at https://github.com/SparebankenVest/azure-key-vault-to-kubernetes.

## Note about installing both Azure Key Vault Env Injector AND Azure Key Vault Controller

If installing both the [Env Injector](../azure-key-vault-env-injector) and the Controller, they share the same Custom Resource Definition (CRD), so only one of them can install it. Set `installCrd` to `false` for either this Chart or the [Controller](../azure-key-vault-controller) Chart. 

## Installing the Chart

```bash
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

```bash
helm install spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s
```

**Note: It is recommended to install akv2k8s in its own dedicated namespace** 

**Note: The Env Injector needs to be anabled for each namespace**

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label, like in the example below:

```
apiVersion: v1
kind: Namespace
metadata:
  name: akv-test
  labels:
    azure-key-vault-env-injection: enabled
```

### Installation of both Env Injector and Controller
```bash
helm install spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s

helm install spv-charts/azure-key-vault-controller \
    --set installCrd=false  --namespace akv2k8s
```

### Using custom authentication with credential injection enabled

```bash
helm install spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s \
  --set customAuth.enabled=true \
  --set customAuth.autoInject.enabled=true \
  --set customAuth.autoInject.secretName=azure-key-vault-secret \
  --set env.AZURE_TENANT_ID=... \
  --set env.AZURE_CLIENT_ID=... \
  --set env.AZURE_CLIENT_SECRET=...
```

## Configuration

The following tables lists configurable parameters of the azure-key-vault-env-injector chart and their default values.

|               Parameter                 |                Description                  |                  Default                 |
| --------------------------------------- | ------------------------------------------- | -----------------------------------------|
|affinity                                 |affinities to use                            |{}                                        |
|customAuth.enabled                       |if custom authentication with azure key vault is enabled |false                         |
|customAuth.autoInject.enabled            |if auto injection of credentials to pods is enabled|false                               |
|customAuth.autoInject.secretName         |name of secret to use to store credentials   |{}                                        |
|customAuth.autoInject.podIdentitySelector|if using aad-pod-identity, which selector to reference|{}                               |
|debug                                    |debug logs for webhook                       |false                                     |
|env                                      |aditional env vars to send to pod            |{}                                        |
|envImage.repository                      |image repo that contains the env image       |spvest/azure-keyvault-env                 |
|envImage.tag                             |image tag                                    |0.1.15                                    |
|image.pullPolicy                         |image pull policy                            |IfNotPresent                              |
|image.repository                         |image repo that contains the controller      |spvest/azure-keyvault-webhook             |
|image.tag                                |image tag                                    |0.1.15                                    |
|installCrd                               |install custom resource definition           |true                                      |
|nodeSelector                             |node selector to use                         |{}                                        |
|podDisruptionBudget.minAvailable         |pod disruption minimum available             |nil                                       |
|podDisruptionBudget.maxUnavailable       |pod disruption maximum unavailable           |nil                                       |
|replicaCount                             |number of replicas                           |1                                         |
|resources                                |resources to request                         |{}                                        |
|service.externalPort                     |webhook service external port                |443                                       |
|service.internalPort                     |webhook service external port                |443                                       |
|service.name                             |webhook service name                         |vault-secrets-webhook                     |
|service.type                             |webhook service type                         |ClusterIP                                 |
|tolerations                              |tolerations to add                           |[]                                        |
