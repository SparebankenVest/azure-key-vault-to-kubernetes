---
title: "Sync Multi Key Value Secret"
description: "Sync a multi-key-value secret from Azure Key Vault into a Kubernetes Secret"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

Sometimes its necessary to have Kubernetes `Secret`'s with multiple keys and values. The problem
is that Secrets in Azure Key Vault has no concept of keys or values. Because of this akv2k8s
have introduced a new type called `multi-key-value-secret`
(see [AzureKeyVaultSecret Object Types](/reference/azure-key-vault-secret/#vault-object-types)).

In order to use `multi-key-value-secret`, just format a Azure Key Vault Secret using `yaml` or `json`:

```yaml
key1: value1
key2: value2
key3: value3
```

or

```json
{
  "key1": "value1",
  "key2": "value2",
  "key3": "value3"
}
```
