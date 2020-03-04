---
title: "Requirements"
description: "Requirements for installing akv2k8s"
---

* Kubernetes version >= 1.13
* Installed a dedicated namespace
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
* Default [authentication](../security/authentication) requires Kubernetes cluster running in Azure - use custom authentication if running outside Azure
