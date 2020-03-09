---
title: "AzureKeyVaultSecret"
description: "Reference of AzureKeyVaultSecret custom resource definition"
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

## Kubernetes Secret Types

The default secret type (`spec.output.secret.type`) is `opaque`. Below is a list of supported Kubernetes secret types and which keys each secret type stores.

For a complete list, see [core/v1/types.go](https://github.com/kubernetes/api/blob/49be0e3344fe443eb3d23105225ed2f1ab1e6cab/core/v1/types.go#L4950) in the Kubernetes GitHub repository.

| Secret type                      | Keys |
| -------------------------------- | ---- |
| `opaque` (default)               | defined in `spec.output.secret.dataKey` |
| `kubernetes.io/tls`              | `tls.key`, `tls.crt` |
| `kubernetes.io/dockerconfigjson` | `.dockerconfigjson` |
| `kubernetes.io/dockercfg`        | `.dockercfg` |
| `kubernetes.io/basic-auth`       | `username`, `password` |
| `kubernetes.io/ssh-auth`         | `ssh-privatekey` |


With the exception of the `opaque` secret type, the Controller will make a best effort to export the Azure Key Vault object into the secret type defined.

### `kubernetes.io/tls`

By pointing to a **exportable** Certificate object in Azure Key Vault AND setting the Kubernetes output secret type to `kubernetes.io/tls`, the controller will automatically format the Kubernetes secret accordingly both for pem and pfx certificates.

### `kubernetes.io/dockerconfigjson`

Requires a well formatted docker config stored in a Secret object like this:

```json
{
  "auths": {
    "some.azurecr.io": {
      "username": "someuser",
      "password": "somepassword",
      "email": "someuser@spv.no",
      "auth": "c29tZXVzZXI6c29tZXBhc3N3b3JkCg=="
    }
  }
}
```

If the `"auth"` property is not included, the controller will generate it.

### `kubernetes.io/basic-auth`

The controller support two formats. Either `username:password` or pre-encoded with base64: `dXNlcm5hbWU6cGFzc3dvcmQ=` stored in a Secret object.

### `kubernetes.io/ssh-auth`

This must be a properly formatted **Private** SSH Key stored in a Secret object.

## Vault Object Types

| Object type   | Description |
| ------------- | ----------- |
| `secret`      | Azure Key Vault Secret - can contain any secret data |
| `certificate` | Azure Key Vault Certificate - A TLS certificate with just the public key or both public and private key if exportable |
| `key`         | Azure Key Vault Key - A RSA or EC key used for signing |
| `multi-key-value-secret`  | A special kind of Azure Key Vault Secret only understood by the Controller and the Env Injector. For cases where a secret contains `json` or `yaml` key/value items that will be directly exported as key/value items in the Kubernetes secret, or access with queries in the Evn Injector. When `multi-key-value-secret` type is used, the `contentType` property MUST also be set to either `application/x-json` or `application/x-yaml`. |
