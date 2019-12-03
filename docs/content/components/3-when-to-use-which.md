---
title: "When to use which?"
metaTitle: "when to use which"
metaDescription: "when to use which"
---

### Recommendation is to install both

The recommendation is to install both the Controller and the Env Injector, enabling native Kubernetes secrets when needed and transparently injecting environment variables for all other cases.

### When to use the Controller 

Use the Controller if:

* the [risks documented with Secrets in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) is acceptable
* there are no concerns about storing Azure Key Vault secrets as base64 encoded plain text values in Kubernetes `Secret` resources
* it is OK that anyone with read access to `Secret` resources in the Kubernetes cluster can read the content of the secrets
* the native `Secret` support in Kubernetes is desired

### When to use the Env Injector? 

Use the Env Injector if:

* any of the [risks documented with Secrets in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) is not acceptable
* there are concerns about storing and exposing base64 encoded Azure Key Vault secrets as Kubernetes `Secret` resources
* preventing Kubernetes users to gain access to Azure Key Vault secret content is important
* the application running in the container support getting secrets as environment variables
* secret environment variable values should not be revealed to Kubernetes resources like Pod specs, stored on disks, visible in logs or exposed in any way other than in-memory for the application 