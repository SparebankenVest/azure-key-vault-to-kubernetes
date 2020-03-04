---
title: "Installation without Helm"
description: "How to setup Azure Key Vault to Kubernetes"
---

Make sure to check the [requirements](requirements) before installing. 

## Dedicated namespace for akv2k8s

We highly recommend: 

1. installing all akv2k8s components into its own dedicated namespace
2. NOT label this namespace with `azure-key-vault-env-injection: enabled`

> If the namespace where the akv2k8s components lives is has the injector enabled (using the label), the Env Injector pod might not be able to start. This is because a mutating webhook will be triggered for every pod about to start in this namespace, which points to the Env Injector pod - which is trying to start - effectively pointing to itself.

If Helm is not an option, use Helm on a local computer to generate the Kubernetes templates like below.

## Helm 2

Add Helm repository:

```bash
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

Render akv2k8s charts locally:

```bash
helm install --debug --dry-run akv2k8s spv-charts/azure-key-vault-controller
  --namespace akv2k8s <options>
helm install --debug --dry-run akv2k8s spv-charts/azure-key-vault-env-injector \
  --set installCrd=false --namespace akv2k8s <options>
```

## Helm 3

Download the Git repository:

```bash
git clone git@github.com:SparebankenVest/c.git
```

Render chart template locally:

```bash
cd public-helm-charts
helm template akv2k8s ./stable/azure-key-vault-env-injector/ <options>
```

## Options and more

For more details about installation options, see the individual Helm charts:

* Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller
* Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector
