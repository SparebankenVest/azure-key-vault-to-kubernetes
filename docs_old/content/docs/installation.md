---
title: "Installation"
metaTitle: "Installation"
metaDescription: "How to setup Azure Key Vault to Kubernetes"
index: 10
---

### Requirements

* Kubernetes version >= 1.9 
* Installed a dedicated namespace
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
* Default [authentication](#authentication) requires Kubernetes cluster running in Azure - use custom authentication if running outside Azure

#### About dedicated namespace

When/if using the Env Injector, we highly recommend installing all akv2k8s components into
its own dedicated namespace, and NOT label this namespace with `azure-key-vault-env-injection: enabled`. If this label exists in a namespace where Env Injector is installed, depending on install sequence, the Env Injector pod might not be able to start. This is because a mutating webhook will be triggered for every pod about to start in this namespace, which points to the Env Injector pod - which is trying to start - effectively pointing to itself.

### Installing to Kubernetes

It's recommended to use Helm charts for installation.

Add Helm repository:

```none
helm repo add spv-charts http://charts.spvapi.no
helm repo update
```

Install both Controller and Env-Injector:

```none
helm install spv-charts/azure-key-vault-controller
  --namespace akv2k8s

helm install spv-charts/azure-key-vault-env-injector \
  --set installCrd=false --namespace akv2k8s
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

### Cleanup

To remove installation, run `helm uninstall`
