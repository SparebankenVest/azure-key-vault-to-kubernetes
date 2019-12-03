---
title: "Get Secret"
metaTitle: "Secret"
metaDescription: "Sync and inject secret from Azure Key Vault"
---

In this section we will show how to:

1. Get a secret from Azure Key Vault into Kubernetes
2. Inject a secret from Azure Key Vault into a container

These are typically mutually exclusive. You will want to do 
(1) if you need the secret in Kubernetes, and (2) if you want 
the secret in your application. In theory you can have both,
but we have not yet come across a good case for doing this.

Requirements:

* Controller must be installed in Kubernetes cluster.
* A Azure Key Vault named `akv2k8s-test`
* A Secret object named `my-secret` stored in Azure Key Vault
* Authentication and Authorization configured

### Get secret from Azure Key Vault into a Kubernetes secret

We start by creating a definition for the Azure Key Vault secret
we want to sync:

```yaml
# secret-sync.yaml

apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: secret-sync 
  namespace: default
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-secret # name of the akv object
      type: secret # akv object type
  output: 
    secret: 
      name: my-secret-from-akv # kubernetes secret name
      dataKey: secret-value # key to store object value in kubernetes secret
```

Apply to Kubernetes:

```bash
$ kubectl apply -f secret-sync.yaml
azurekeyvaultsecret.spv.no/secret-sync created
```

List AzureKeyVaultSecret's:

```bash
$ kubectl -n default get akvs
NAME          VAULT          VAULT OBJECT   SECRET NAME   SYNCHED
secret-sync   akv2k8s-test   my-secret 
```

### Inject secret from Azure Key Vault into a container