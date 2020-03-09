---
title: "Overview"
description: "Different options for installing akv2k8s"
---

Make sure to check the [requirements](installation/requirements) before installing. 

## Dedicated namespace for akv2k8s

Akv2k8s should be installed in a dedicated Kubernetes namespace and **NOT** label this namespace with `azure-key-vault-env-injection: enabled`.

> If the namespace where the akv2k8s components is installed has the injector enabled (`azure-key-vault-env-injection: enabled`), the Env Injector will most likely not be able to start. This is because a mutating webhook will be triggered for every pod about to start in this namespace, which points to the Env Injector pod - which is trying to start - effectively pointing to itself.

## Installation options

It's recommended to use Helm charts for installation.

[Installing with Helm charts](installation/installing-with-helm)

[Installing witouh Helm charts](installation/installing-without-helm)
