---
title: "Upgrading  with Helm"
description: "How to update Azure Key Vault to Kubernetes with Helm"
---

Update Helm repository:

```bash
helm repo update
```

Update both Controller and Env-Injector:

```bash
helm upgrade azure-key-vault-controller \
  spv-charts/azure-key-vault-controller \
  --namespace akv2k8s
  --set installCrd=false \
  <aditional values used during install>

helm install azure-key-vault-env-injector \
  spv-charts/azure-key-vault-env-injector \
  --namespace akv2k8s
  --set installCrd=false \
  <aditional values used during install>
```

> **Note: It's important that you set `--set installCrd=false`, because in a existing installation the CRD already exists.**

For more details about installation options, see the 
individual Helm charts:

* [Controller](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller/README.md)
* [Env Injector](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/stable/azure-key-vault-env-injector/README.md)
