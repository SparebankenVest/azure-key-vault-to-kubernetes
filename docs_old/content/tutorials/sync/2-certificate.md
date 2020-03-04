---
title: "Sync Certificate"
metaTitle: "Sync Certificate"
metaDescription: "Tutorial covering how to get sync a certificate from Azure Key Vault into a native Kubernetes Secret."
index: 55
---

<div class="alert alert-warning" role="alert">
  Note: The <a href="/tutorials/0-prerequisites">prerequisites</a> are required to complete this tutorial.
</div>

*This tutorial will cover how to sync a certificate from Azure Key Vault into a native Kubernetes Secret.*

We start by creating a definition for the Azure Key Vault secret pointing to the certificate
we want to sync (certificate created in [prerequisites](/tutorials/0-prerequisites)):

```yaml
# certificate-sync.yaml

apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: certificate-sync 
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-certificate
      type: certificate
  output: # Only needed by the Controller
    secret:
      name: my-certificate-from-akv # kubernetes secret name
      type: kubernetes.io/tls
```

Apply to Kubernetes:

```bash
$ kubectl apply -f certificate-sync.yaml
azurekeyvaultsecret.spv.no/certificate-sync created
```

To list AzureKeyVaultSecret's and see sync status:

```bash
$ kubectl -n akv-test get akvs
NAME               VAULT          VAULT OBJECT    SECRET NAME         SYNCHED
certificate-sync   akv2k8s-test   my-certificate  my-secret-from-akv
```

Shortly a Kubernetes secret of type `kubernetes.io/tls` should exist:

```bash
$ kubectl -n akv-test get secret
NAME                     TYPE               DATA  AGE
my-certificate-from-akv  kubernetes.io/tls  3     1m 
```

Inspect the Kubernetes secret:

```bash
kubectl -n akv-test get secret my-certificate-from-akv -o yaml
```

The created Kubernetes Secret should look something like this:

```yaml
apiVersion: v1
data:
  tls.crt: ...
  tls.key: ...
kind: Secret
metadata:
  name: keyvault-certificate
  namespace: default
type: kubernetes.io/tls
```