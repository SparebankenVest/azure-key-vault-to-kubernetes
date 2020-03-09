---
title: "Requirements"
description: "Requirements for installing akv2k8s"
---

* Kubernetes version >= 1.13
* A dedicated kubernetes namespace
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
* Default [authentication](../security/authentication) requires Kubernetes cluster running in Azure - use [custom authentication](../security/authentication#custom-authentication) if running outside Azure
