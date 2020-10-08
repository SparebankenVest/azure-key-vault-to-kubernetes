---
title: "Installation without Helm"
description: "How to setup Azure Key Vault to Kubernetes"
---

Make sure to check the [requirements](requirements) before installing. 

If Helm is not an option, use Helm on a local computer to generate the Kubernetes templates like below.

## Using Helm 3

Download the Git repository:

```bash
git clone git@github.com:SparebankenVest/public-helm-charts.git
```

Render chart templates locally:

```bash
cd public-helm-charts
helm template azure-key-vault-controller ./stable/azure-key-vault-controller/ <options>
helm template azure-key-vault-env-injector ./stable/azure-key-vault-env-injector/ <options>
```

## Options and more

For more details about installation options, see the [Helm chart](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/akv2k8s)