---
title: "Requirements"
description: "Requirements for installing akv2k8s"
---

* Kubernetes version >= 1.13
* A dedicated kubernetes namespace
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
* Default [authentication](../security/authentication) requires Kubernetes cluster running in Azure - use [custom authentication](../security/authentication#custom-authentication) if running outside Azure

## Dedicated namespace for akv2k8s

Akv2k8s should be installed in a dedicated Kubernetes namespace that is **NOT** label with `azure-key-vault-env-injection: enabled`.

**If the namespace where the akv2k8s components is installed has the injector enabled (`azure-key-vault-env-injection: enabled`), the Env Injector will most likely not be able to start.** This is because the Env Injector mutating webhook will trigger for every pod about to start in namespaces where enabled, and in the home namepsace of the Env Injector, it will effectively point to itself, which does not exist yet.

**The simple rule to avoid any issues related to this, is to just install akv2k8s components in its own dedicated namespace.**