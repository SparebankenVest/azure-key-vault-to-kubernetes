---
title: "Vault Object Types"
description: "See the complete reference and options for all akv2k8s resources."
---

| Object type   | Description |
| ------------- | ----------- |
| `secret`      | Azure Key Vault Secret - can contain any secret data |
| `certificate` | Azure Key Vault Certificate - A TLS certificate with just the public key or both public and private key if exportable |
| `key`         | Azure Key Vault Key - A RSA or EC key used for signing |
| `multi-key-value-secret`  | A special kind of Azure Key Vault Secret only understood by the Controller and the Env Injector. For cases where a secret contains `json` or `yaml` key/value items that will be directly exported as key/value items in the Kubernetes secret, or access with queries in the Evn Injector. When `multi-key-value-secret` type is used, the `contentType` property MUST also be set to either `application/x-json` or `application/x-yaml`. |

See [Examples](../examples) for different usages.

