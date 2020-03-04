---
title: "Sync Secret"
metaTitle: "Sync Secret"
metaDescription: "Tutorial covering how to get a secret from Azure Key Vault into Kubernetes, either as a native Kubernetes secret or directly injected into a container."
index: 55
---

<div class="alert alert-warning" role="alert">
  Note: The <a href="/tutorials/0-prerequisites">prerequisites</a> are required to complete this tutorial.
</div>

**This tutorial will cover how to sync a secret from Azure Key Vault into a native Kubernetes Secret.**

We start by creating a definition for the Azure Key Vault secret
we want to sync:

```yaml
# secret-sync.yaml

apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: secret-sync 
  namespace: akv-test
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
$ kubectl -n akv-test get akvs
NAME          VAULT          VAULT OBJECT   SECRET NAME         SYNCHED
secret-sync   akv2k8s-test   my-secret      my-secret-from-akv  
```

Shortly a Kubernetes secret should exist:

```bash
$ kubectl -n akv-test get secret
NAME                TYPE    DATA  AGE
my-secret-from-akv  Opaque  1     1m 
```

### Cleanup

```bash
kubectl -n akv-test delete AzureKeyVaultSecret secret-sync 
```