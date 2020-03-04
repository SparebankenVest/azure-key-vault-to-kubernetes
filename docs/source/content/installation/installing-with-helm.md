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

## Installing with Helm

Add Helm repository:

```bash
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

Install both Controller and Env-Injector:

```bash
helm install spv-charts/azure-key-vault-controller
  --namespace akv2k8s

helm install spv-charts/azure-key-vault-env-injector \
  --set installCrd=false --namespace akv2k8s
```

For more details about installation options, see the 
individual Helm charts:

* Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller
* Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector
