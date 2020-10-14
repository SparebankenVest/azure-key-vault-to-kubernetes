---
title: "Sync Signing Key"
description: "Sync signing key from Azure Key Vault into a Kubernetes Secret"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

We start by creating a definition for the Azure Key Vault signing-key we want to sync:

```yaml:title=akvs-signing-key-sync.yaml
apiVersion: spv.no/v1
kind: AzureKeyVaultSecret
metadata:
  name: signing-key-sync 
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-key # name of the akv object
      type: key # akv object type
  output: 
    secret: 
      name: my-signing-key-from-akv # kubernetes secret name
      dataKey: signing-key # key to store object value in kubernetes secret
```

Apply to Kubernetes:

```bash
$ kubectl apply -f akvs-signing-key-sync.yaml
azurekeyvaultsecret.spv.no/signing-key-sync created
```

List AzureKeyVaultSecret's:

```bash
$ kubectl -n akv-test get akvs
NAME              VAULT         VAULT OBJECT  SECRET NAME              SYNCHED
signing-key-sync  akv2k8s-test  my-key        my-signing-key-from-akv  
```

Shortly a Kubernetes secret should exist:

```bash
$ kubectl -n akv-test get secret
NAME                     TYPE    DATA  AGE
my-signing-key-from-akv  Opaque  1     1m 
```

### Cleanup

```bash
kubectl delete -f akvs-signing-key-sync.yaml
```