---
title: "Examples"
metaTitle: "Examples"
metaDescription: "See different examples of how akv2k8s can be used."
index: 60
---

### Plain secret

Define a `AzureKeyVaultSecret` resource:

```yaml 
apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: my-first-azure-keyvault-secret
  namespace: default
spec:
  vault:
    name: my-kv # name of key vault
    object:
      type: secret # object type
      name: test-secret # name of the object
  output: # Only needed by the Controller
    secret:
      name: keyvault-secret
      dataKey: azuresecret # key to store object value in kubernetes secret
```

If the Controller is installed the following Kubernetes Secret will be created:

```yaml
apiVersion: v1
data:
  azuresecret: YXNkZmFzZGZhc2Rm
kind: Secret
metadata:
  name: keyvault-secret
  namespace: default
type: opaque
```

If Env Injector is installed, inject secret by referencing the **AzureKeyVaultSecret** above using a replacement marker (`<AzureKeyVaultSecret>@azurekeyvault`)`:

```yaml
...
containers:
  - name: alpine
    env:
    - name: MY_SECRET
      value: my-first-azure-keyvault-env-secret@azurekeyvault
...
```

### Base64 Encoded Secret

Base64 encoded secret is supported only for Controller because it's meant to be used with files stored in the Azure Key Vault.

Create Azure Key Vault secret containing binary file in base64 decoded format.

```bash
base64_tokendata=$( openssl base64 -A -in ./my-keystore.jks )
az keyvault secret set --vault-name my-kv --name my-keystore --value "$base64_tokendata"
```

Define a `AzureKeyVaultSecret` resource:

```yaml
apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: my-first-azure-keyvault-secret
  namespace: default
spec:
  vault:
    name: my-kv # name of key vault
    object:
      type: base64-encoded-secret # object type
      name: my-keystore # name of the object
  output: # Only needed by the Controller
    secret:
      name: keyvault-secret
      dataKey: azuresecret.jks # key to store object value in kubernetes secret
```

If the Controller is installed the following Kubernetes Secret will be created:

```yaml
apiVersion: v1
data:
  azuresecret: YXNkZmFzZGZhc2Rm
kind: Secret
metadata:
  name: keyvault-secret.jks
  namespace: default
type: opaque
```

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
