---
title: "AzureKeyVaultSecret"
description: "See the complete reference and options for all akv2k8s resources."
---

The `AzureKeyVaultSecret` is defined using this schema:

```yaml
apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: < name for azure key vault secret>
  namespace: <namespace for azure key vault secret>
spec:
  vault:
    name: <name of azure key vault>
    object:
      name: <name of azure key vault object to sync>
      type: <object type in azure key vault to sync>
      version: <optional - version of object to sync>
      contentType: <only used when type is the special multi-key-value-secret - either application/x-json or application/x-yaml>
  output: # ignored by env injector, required by controller to output kubernetes secret
    secret: 
      name: <name of the kubernetes secret to create>
      dataKey: <required when type is opaque - name of the kubernetes secret data key to assign value to - ignored for all other types>
      type: <optional - kubernetes secret type - defaults to opaque>
```

> **Note - the `output` is only used by the Controller to create the Azure Key Vault secret as a Kubernetes native Secret - it is ignored and not needed by the Env Injector.**

