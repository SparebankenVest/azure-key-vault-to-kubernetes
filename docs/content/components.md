---
title: "Components"
metaTitle: "components"
metaDescription: "Learn about the different components of akv2k8s."
---

Azure Key Vault to Kubernetes contains two components:

* [Azure Key Vault Controller](/components/1-controller)
* [Azure Key Vault Env Injector](/components/2-env-injector)

The **Azure Key Vault Controller** (Controller for short) is for synchronizing Secrets, Certificates and Keys from Azure Key Vault to native `Secret`'s in Kubernetes.

The **Azure Key Vault Env Injector** (Env Injector for short) is a Kubernetes Mutating Webhook that transparently injects Azure Key Vault secrets as environment variables into programs running in containers, without touching disk or in any other way expose the actual secret content outside the program.