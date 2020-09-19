---
title: "Installation with Helm"
description: "How to install Azure Key Vault to Kubernetes with Helm"
---

> Make sure to check the [requirements](requirements) before installing. 

Before installing the Chart, the Custom Resource Definition must be installed, by pointing to the correct version:

```
kubectl apply -f https://raw.githubusercontent.com/sparebankenvest/azure-key-vault-to-kubernetes/{{ version }}/crds/AzureKeyVaultSecret.yaml
```

E.g. for version 1.1.0 use:

```
https://raw.githubusercontent.com/sparebankenvest/azure-key-vault-to-kubernetes/crd-1.1.0/crds/AzureKeyVaultSecret.yaml
```

A dedicated namespace needs to be created for akv2k8s:

```bash
kubectl create ns akv2k8s
```

## Installing with Helm on Azure AKS


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

For more details about installation options, see the 
individual Helm charts:

* [Controller](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller/README.md)
* [Env Injector](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector/README.md)

## Installing with Helm outside Azure AKS 

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

## Installing with Helm for akv2k8s versions < 1.1.0

> Helm charts prior to version 1.1.0 installed the Azure Key Vault Secret CRD as part of the Helm chart. As [documented by Helm](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/), this has its drawbacks and we decided to handle the CRD outside of Helm for versions >= 1.1.0. 

For akv2k8s versions < 1.1.0 we need to tell Helm NOT to install the CRD for the second Chart, setting `installCrd=false`:

```bash
helm upgrade -i azure-key-vault-controller spv-charts/azure-key-vault-controller \
  --namespace akv2k8s

helm upgrade -i azure-key-vault-env-injector spv-charts/azure-key-vault-env-injector \
  --set installCrd=false \
  --namespace akv2k8s
```