---
title: "Setup"
metaTitle: "Setup"
metaDescription: "Installation of Azure Key Vault to Kubernetes"
index: 10
---

### Requirements

* Kubernetes version >= 1.9 
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
* Default [authentication](#authentication) requires Kubernetes cluster running in Azure - use custom authentication if running outside Azure

### Installation

It's recommended to use Helm charts for installation.

Add Helm repository:

```none
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

Install both Controller and Env-Injector:

```none
helm install spv-charts/azure-key-vault-controller \
  --set installCrd=false

helm install spv-charts/azure-key-vault-env-injector
```

For more details about installation options, see the 
individual Helm charts:

* Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller
* Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector

### Installation without Helm

If Helm is not an option, use Helm on a local computer to generate the Kubernetes templates like below:

```none
helm install --debug --dry-run <options>
```

See the individual Helm charts above for `<options>`.