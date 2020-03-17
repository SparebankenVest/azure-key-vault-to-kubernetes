---
title: "Authorization"
description: "Learn how to set the proper access rights in Azure Key Vault"
---

No matter which [authentication](authentication) option is used, the authenticated account will need `get` permissions to the different object types in Azure Key Vault.

**Note: It's only possible to control access at the top level of Azure Key Vault, not per object/resource. The recommendation is therefore to have a dedicated Key Vault per cluster.**

Access is controlled through Azure Key Vault policies and can be configured through Azure CLI like this:

Azure Key Vault Secrets:

```bash
az keyvault set-policy \
  -n <azure key vault name> \
  --secret-permissions get \
  --spn <service principal id> \ 
  --subscription <azure subscription>
```

Azure Key Vault Certificates:

```bash
az keyvault set-policy \
  -n <azure key vault name> \
  --certificate-permissions get \
  --spn <service principal id> \
  --subscription <azure subscription>
```

Azure Key Vault Keys:

```bash
az keyvault set-policy \
  -n <azure key vault name> \
  --key-permissions get \
  --spn <service principal id> \
  --subscription <azure subscription>
```
