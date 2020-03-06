---
title: "Azure Key Vault Controller Helm Chart"
description: "Azure Key Vault Controller reference"
---

This chart will install a Kubernetes controller and a Custom Resource Definition (`AzureKeyVaultSecret`), that together enable secrets from Azure Key Vault to be stored as Kubernetes native `Secret` resources.

For more information see the main GitHub repository at https://github.com/SparebankenVest/azure-key-vault-to-kubernetes.

## Note about installing both Azure Key Vault Controller AND Azure Key Vault Env Injector

If installing both the Controller and the [Env Injector](../azure-key-vault-env-injector), they share the same Custom Resource Definition (CRD), so only one of them can install it. Set `installCrd` to `false` for either this Chart or the [Env Injector](../azure-key-vault-env-injector) Chart. 

## Installing the Chart

```bash
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

```bash
helm install spv-charts/azure-key-vault-controller \
  --namespace akv2k8s
```

**Installation of both Controller and env-injector**
```bash
helm install spv-charts/azure-key-vault-controller \
  --namespace akv2k8s
helm install spv-charts/azure-key-vault-env-injector \
  --set installCrd=false  --namespace akv2k8s
```

We set `installCrd=false` on the last helm chart we install, or else the second install (injector in this case) will fail when the CRD already exists.

**Using custom authentication**

```bash
helm install spv-charts/azure-key-vault-env-injector \
  --set keyVault.customAuth.enabled=true \
  --set env.AZURE_TENANT_ID=... \
  --set env.AZURE_CLIENT_ID=... \
  --set env.AZURE_CLIENT_SECRET=...
```

## Configuration

The following table lists configurable parameters of the azure-key-vault-controller chart and their default values.

|               Parameter                |                Description                   |                  Default                 |
| -------------------------------------- | -------------------------------------------- | -----------------------------------------|
|env                                     |aditional env vars to send to pod             |{}                                        |
|image.repository                        |image repo that contains the controller image | spvest/azure-keyvault-controller         |
|image.tag                               |image tag|0.1.15|
|installCrd                              |install custom resource definition           |true                                      |
|keyVault.customAuth.enabled             |if custom auth is enabled | false |
|keyVault.customAuth.podIdentitySelector |if using aad-pod-identity, which selector to reference | "" |
|keyVault.polling.normalInterval         |interval to wait before polling azure key vault for secret updates | 1m |
|keyVault.polling.failureInterval        |interval to wait when polling has failed `failureAttempts` before polling azure key vault for secret updates | 5m |
|keyVault.polling.failureAttempts        |number of times to allow secret updates to fail before applying `failureInterval` | 5 |
|logLevel                                | log level | info |
