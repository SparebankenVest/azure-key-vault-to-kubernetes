---
title: "Installation with Helm"
description: "How to install Azure Key Vault to Kubernetes with Helm"
---

> Make sure to check the [requirements](requirements) before installing. 

## Installing the AzureKeyVaultSecret CRD

Before installing the Chart, the Custom Resource Definition for AzureKeyVaultSecret must be installed by pointing to the correct version:

```
kubectl apply -f https://raw.githubusercontent.com/sparebankenvest/azure-key-vault-to-kubernetes/{{ version }}/crds/AzureKeyVaultSecret.yaml
```

For the latest version (`1.1.0`) run:

```
kubectl apply -f https://raw.githubusercontent.com/sparebankenvest/azure-key-vault-to-kubernetes/crd-1.1.0/crds/AzureKeyVaultSecret.yaml
```

## Create a dedicated namespace

A dedicated namespace needs to be created for akv2k8s:

```bash
kubectl create ns akv2k8s
```

## Installation

### Installing with Helm on Azure AKS

Add Helm repository:

```bash
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

Install both Controller and Env-Injector:

```bash
helm upgrade -i azure-key-vault-controller spv-charts/azure-key-vault-controller \
    --namespace akv2k8s

helm upgrade -i azure-key-vault-env-injector spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s
```

For more details about installation options, see the [Helm chart for akv2k8s](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/akv2k8s):

### Installing with Helm outside Azure AKS 

When running inside Azure AKS, akv2k8s will use the AKS cluster credentials by default to authenticate with Azure Key Vault. Outside Azure AKS - credentials must be provided by setting `keyVault.customAuth=true` and provide credentials as documentend under [Authentication](../security/authentication) for more details.

Create `akv2k8s` namespace:

```bash
kubectl create ns akv2k8s
```

Add Helm repository:

```bash
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

Install both Controller and Env-Injector:

```bash
helm upgrade -i azure-key-vault-controller spv-charts/azure-key-vault-controller \
   --namespace akv2k8s \
   --set keyVault.customAuth.enabled=true \
   --set env.AZURE_TENANT_ID=<tenant-id> \
   --set env.AZURE_CLIENT_ID=<client-id> \
   --set env.AZURE_CLIENT_SECRET=<client-secret>

helm upgrade -i azure-key-vault-env-injector spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s \
  --set keyVault.customAuth.enabled=true \
  --set env.AZURE_TENANT_ID=<tenant-id> \
  --set env.AZURE_CLIENT_ID=<client-id> \
  --set env.AZURE_CLIENT_SECRET=<client-secret>
```
