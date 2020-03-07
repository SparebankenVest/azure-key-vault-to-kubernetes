---
title: "Installation with Helm"
description: "How to install Azure Key Vault to Kubernetes with Helm"
---

Make sure to check the [requirements](requirements) before installing. 

## Dedicated namespace for akv2k8s

We highly recommend: 

1. installing all akv2k8s components into its own dedicated namespace
2. NOT label this namespace with `azure-key-vault-env-injection: enabled`

> If the namespace where the akv2k8s components lives is has the injector enabled (using the label), the Env Injector pod might not be able to start. This is because a mutating webhook will be triggered for every pod about to start in this namespace, which points to the Env Injector pod - which is trying to start - effectively pointing to itself.

## Installing with Helm on Azure AKS

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
helm install azure-key-vault-controller \
  spv-charts/azure-key-vault-controller \
  --namespace akv2k8s

helm install azure-key-vault-env-injector \
  spv-charts/azure-key-vault-env-injector \
  --set installCrd=false \
  --namespace akv2k8s
```

For more details about installation options, see the 
individual Helm charts:

* Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller
* Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector

## Installing with Helm outside Azure AKS

When running inside Azure AKS, akv2k8s can use the AKS cluster credentials for authorizing with Azure Key Vault (default behavior). Outside Azure AKS - credentials (Azure Service Principal) must be provided by setting `keyVault.customAuth=true`. See [Authentication](security/authentication) for more details.

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
helm install azure-key-vault-controller \
  spv-charts/azure-key-vault-controller \
   --namespace akv2k8s \
   --set keyVault.customAuth.enabled=true \
   --set env.AZURE_TENANT_ID=<tenant-id> \
   --set env.AZURE_CLIENT_ID=<client-id> \
   --set env.AZURE_CLIENT_SECRET=<client-secret>

helm install azure-key-vault-env-injector \
  spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s \
  --set installCrd=false \
  --set keyVault.customAuth.enabled=true \
  --set env.AZURE_TENANT_ID=<tenant-id> \
  --set env.AZURE_CLIENT_ID=<client-id> \
  --set env.AZURE_CLIENT_SECRET=<client-secret>
```