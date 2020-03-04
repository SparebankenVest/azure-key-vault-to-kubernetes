---
title: "Kubernetes Secret Types"
description: "See the complete reference and options for all akv2k8s resources."
---

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

## `kubernetes.io/tls`

By pointing to a **exportable** Certificate object in Azure Key Vault AND setting the Kubernetes output secret type to `kubernetes.io/tls`, the controller will automatically format the Kubernetes secret accordingly both for pem and pfx certificates.

## `kubernetes.io/dockerconfigjson`

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

## `kubernetes.io/basic-auth`

The controller support two formats. Either `username:password` or pre-encoded with base64: `dXNlcm5hbWU6cGFzc3dvcmQ=` stored in a Secret object.

## `kubernetes.io/ssh-auth`

This must be a properly formatted **Private** SSH Key stored in a Secret object.