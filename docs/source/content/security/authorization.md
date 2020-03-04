---
title: "Authorization"
description: "Learn how to set the proper access rights to access Azure Key Vault secrets from Kubernetes."
---

No matter which authentication option is used, the authenticated account will need `get` permissions to the different object types in Azure Key Vault.

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

**Note: The Env Injector needs to be anabled for each namespace**

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label, like in the example below:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: akv-test
  labels:
    azure-key-vault-env-injection: enabled
```
