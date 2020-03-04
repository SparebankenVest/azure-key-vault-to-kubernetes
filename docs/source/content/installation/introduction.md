---
title: "Introduction"
description: "Different options for installing akv2k8s"
---

Make sure to check the [requirements](requirements) before installing. 

## Dedicated namespace for akv2k8s

We highly recommend: 

1. installing all akv2k8s components into its own dedicated namespace
2. NOT label this namespace with `azure-key-vault-env-injection: enabled`

> If the namespace where the akv2k8s components lives is has the injector enabled (using the label), the Env Injector pod might not be able to start. This is because a mutating webhook will be triggered for every pod about to start in this namespace, which points to the Env Injector pod - which is trying to start - effectively pointing to itself.

## Installation options

It's recommended to use Helm charts for installation.

[Installing with Helm charts](installing-with-helm)

[Installing witouh Helm charts](installing-without-helm)
