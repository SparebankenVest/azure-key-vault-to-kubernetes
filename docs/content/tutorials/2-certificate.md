---
title: "Get Certificate"
metaTitle: "Get Certificate"
metaDescription: "Tutorial covering how to get a certificate from Azure Key Vault into Kubernetes, either as a native Kubernetes secret or directly injected into a container."
index: 53
---

**Note: The [prerequisites](/tutorials/0-prerequisites) are required to complete this tutorial.**

### Certificate with exportable key

Define a `AzureKeyVaultSecret` resource:

```yaml
apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: my-first-azure-keyvault-certificate
  namespace: default
spec:
  vault:
    name: my-kv
    object:
      type: certificate
      name: test-cert
  output: # Only needed by the Controller
    secret:
      name: keyvault-certificate
      type: kubernetes.io/tls
```

If Controller is installed the following Kubernetes Secret will be created:

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

Note that since `spec.output.secret.type=kubernetes.io/tls` a Kubernetes Secret of type `kubernetes.io/tls` was created.

If Env Injector is installed, inject secret by referencing the **AzureKeyVaultSecret** above using a replacement marker (`azurekeyvault@<AzureKeyVaultSecret>`) and query (`?`) to point to private/public key:

```yaml
...
containers:
  - name: alpine
    env:
    - name: PUBLIC_KEY
      value: my-first-azure-keyvault-env-certificate@azurekeyvault?tls.crt
    - name: PRIVATE_KEY
      value: my-first-azure-keyvault-env-certificate@azurekeyvault?tls.key
...
```
