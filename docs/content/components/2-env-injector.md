---
title: "Env Injector"
metaTitle: "Env Injector"
metaDescription: "Learn about the Env-Injector for Azure Key Vault to Kubernetes."
---

The **Azure Key Vault Env Injector** (Env Injector for short) is a Kubernetes Mutating Webhook that transparently injects Azure Key Vault secrets as environment variables into programs running in containers, without touching disk or in any other way expose the actual secret content outside the program.

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. As with the Controller, the Env Injector relies on `AzureKeyVaultSecret` resources to provide information about the Azure Key Vault secrets. 

The Env Injector will start processing containers containing one or more environment placeholders like below: 

```yaml
env:
  - name: <name of environment variable>
    value: <name of AzureKeyVaultSecret>@azurekeyvault?<optional field query>
```

**Note: To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label**

It will start by injecting a init-container into the Pod. This init-container copies over the `azure-keyvault-env` executable to a share volume between the init-container and the original container. It then changes either the CMD or ENTRYPOINT, depending on which was used by the original container, to use the `azure-keyvault-env` executable instead, and pass on the "old" command as parameters to this new executable. The init-container will then complete and the original container will start.

When the original container starts it will execute the `azure-keyvault-env` command which will download any Azure Key Vault secrets, identified by the environment placeholders above. The remaining step is for `azure-keyvault-env` to execute the original command and params, pass on the updated environment variables with real secret values. This way all secrets gets injected transparently in-memory during container startup, and not reveal any secret content to the container spec, disk or logs.
