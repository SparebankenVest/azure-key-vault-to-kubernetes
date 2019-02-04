# Azure Key Vault Secrets for Kubernetes

A Kubernetes controller synchronizing Secrets, Certificates and Keys from Azure Key Vault to `Secret`'s in Kubernetes.

**Problem:** "I have to manually extract secrets from Azure Key Vault and apply them as Secrets in Kubernetes."

**Solution:** "Install the `azure-keyvault-controller` and automatically synchronize objects from Azure Key Vault as secrets in Kubernetes."

<!-- TOC depthFrom:2 depthTo:3 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Understand this!](#understand-this)
- [How it works](#how-it-works)
- [Authentication](#authentication)
- [Azure Key Vault Authorization](#azure-key-vault-authorization)
- [Installation](#installation)
- [Usage](#usage)
	- [Vault object types](#vault-object-types)
	- [Commonly used Kubernetes secret types](#commonly-used-kubernetes-secret-types)
- [Examples](#examples)
	- [Getting a plain secret from Azure Key Vault](#getting-a-plain-secret-from-azure-key-vault)
	- [Getting a certificate with exportable key from Azure Key Vault](#getting-a-certificate-with-exportable-key-from-azure-key-vault)

<!-- /TOC -->

## Understand this!

The same [risks as documented with `Secret`'s in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) also apply for the `azure-keyvault-controller`, with the exception of:

_... If you configure the secret through a manifest (JSON or YAML) file which has the secret data encoded as base64, sharing this file or checking it in to a source repository means the secret is compromised. Base64 encoding is not an encryption method and is considered the same as plain text. ..._

**One of the main reasons for creating this controller was to mitigate the risk above. Using the `azure-keyvault-controller` and the `AzureKeyVaultSecret` prevent secrets from being checked into source control or unintentionally be exposed by other means.**

Make sure you fully understand these risks before synchronizing any Azure Key Vault secrets to Kubernetes.

## How it works

Using the custom `AzureKeyVaultSecret` Kubernetes resource the `azure-keyvault-controller` will synchronize Azure Key Vault objects (secrets, certificates and keys) into Kubernetes `Secret`'s.

After the resource is applied to Kubernetes, the controller will try to retreive the specified object from Azure Key Vault and apply it as a Kubernetes `secret`. Later the controller will periodically poll Azure Key Vault to check if the object has changed, and if so apply the change to the Kubernetes `secret`.

See [Usage](#usage) for more information.

## Authentication

The `azure-keyvault-controller` use environment-based authentication as documented here: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication

Note: Using Managed Service Identity (MSI) requires the [`azure-pod-identity`](https://github.com/Azure/aad-pod-identity) controller running and configured in the cluster.

The two most common authentication methods are MSI and Client Credentials (Service Principal).

At the time of writing the following authentication options was available (extracted from the Microsoft doc about environment-based authentication above):

| Authentication type |	Environment variable |	Description |
| ------------------- | -------------------- | ------------ |
| Client credentials 	| AZURE_TENANT_ID 	   | The ID for the Active Directory tenant that the service principal belongs to. |
|                     |	AZURE_CLIENT_ID 	   | The name or ID of the service principal. |
|                     |	AZURE_CLIENT_SECRET  | The secret associated with the service principal. |
| Certificate 	      | AZURE_TENANT_ID      | The ID for the Active Directory tenant that the certificate is registered with. |
|                     | AZURE_CLIENT_ID      | The application client ID associated with the certificate. |
|                     | AZURE_CERTIFICATE_PATH | The path to the client certificate file. |
|                     | AZURE_CERTIFICATE_PASSWORD | The password for the client certificate. |
| Username/Password   | AZURE_TENANT_ID | The ID for the Active Directory tenant that the user belongs to. |
|                     | AZURE_CLIENT_ID | The application client ID. |
|                     | AZURE_USERNAME  | The username to sign in with.
|                     | AZURE_PASSWORD  | The password to sign in with. |

## Azure Key Vault Authorization

The account which the controller is running under must have Azure Key Vault `get` permissions to the object types (secret, certificate and key) that is going to be synchronized with Kubernetes. This is controlled through Azure Key Vault policies and can be configured through Azure CLI like this:

Azure Key Vault Secrets:

`az keyvault set-policy -n <azure key vault name> --secret-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Certificates:

`az keyvault set-policy -n <azure key vault name> --certificate-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Keys:

`az keyvault set-policy -n <azure key vault name> --key-permissions get --spn <service principal id> --subscription <azure subscription>`

## Installation

**1. Deploy the Custom Resource Definition for AzureKeyVaultSecret**

The CRD can be found here: [artifacts/crd.yaml](artifacts/crd.yaml)

**2. Deploy controller**

An example deployment definition can be found here: [artifacts/example-controller-deployment.yaml](artifacts/example-controller-deployment.yaml)

Optional environment variables:

| Env var                              | Description | Default |
| ------------------------------------ | ----------- | ------- |
| AZURE_VAULT_NORMAL_POLL_INTERVALS    | Duration to wait between polls to Azure Key Vault for changes | 1m |
| AZURE_VAULT_EXCEPTION_POLL_INTERVALS | Duration to wait between polls to Azure Key Vault for changes, after AZURE_VAULT_MAX_FAILURE_ATTEMPTS is reached | 5m |
| AZURE_VAULT_MAX_FAILURE_ATTEMPTS     | How many failures are accepted before reducing the frequency to Slow | "5" |
| LOG_LEVEL                            | Log level to use for output logs. Options are `trace`, `debug`, `info`, `warning`, `error`, `fatal` or `panic`. | info |

In addition there are environment variables for controlling **Azure authentication** which is documented by Microsoft here: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication and describe above in the Authentication section.

## Usage
After you have installed the `azure-keyvault-controller`, you can create `AzureKeyVaultSecret` resources.

The `AzureKeyVaultSecret` is defined using this schema:

```yaml
apiVersion: azure-keyvault-controller.spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: <name for azure key vault secret>
  namespace: <namespace for azure key vault secret>
spec:
  vault:
    name: <name of azure key vault>
    object:
      name: <name of azure key vault object to sync>
      type: <object type in azure key vault to sync>
      version: <optional - version of object to sync>
      contentType: <only applicable when type is the special multi-key-value-secret - either application/x-json or application/x-yaml>
  output:
    secret:
      name: <optional - name of the kubernetes secret to create - defaults to this resource metadata.name>
      dataKey: <required when type is opaque - name of the kubernetes secret data key to assign value to - ignored for all other types>
      type: <optional - kubernetes secret type - defaults to opaque>
```

See [Examples](#examples) for different usages.

### Vault object types

| Object type   | Description |
| ------------- | ----------- |
| `secret`      | Azure Key Vault Secret - can contain any secret data |
| `certificate` | Azure Key Vault Certificate - A TLS certificate with just the pulic key or both public and private key if exportable |
| `key`         | Azure Key Vault Key - A RSA or EC key used for signing |

In addition the controller accepts the special `multi-key-value-secret` type that will allow a Azure Key Vault Secret object to contain `json` or `yaml` key/value items that will be directly exported as key/value items in the Kubernetes secret. When `multi-key-value-secret` type is used, the `contentType` property MUST also be set with either `application/x-json` or `application/x-yaml`.

### Commonly used Kubernetes secret types

For a complete list: https://github.com/kubernetes/api/blob/49be0e3344fe443eb3d23105225ed2f1ab1e6cab/core/v1/types.go#L4950

| Secret type                      | Keys |
| -------------------------------- | ---- |
| `opaque`                         | defined in `spec.output.secret.dataKey` |
| `kubernetes/tls`                 | `tls.key`, `tls.crt` |
| `kubernetes.io/dockerconfigjson` | `.dockerconfigjson` |
| `kubernetes.io/basic-auth`       | `username`, `password` |
| `kubernetes.io/ssh-auth`         | `ssh-privatekey` |


With the exception of the `opaque` secret type, the controller will make a best effort to export the Azure Key Vault object into the secret type defined.

__**kubernetes/tls**__

By pointing to an exportable Certificate object in Azure Key Vault AND setting the Kubernetes output secret type to `kubernetes/tls`, the controller will automatically format the Kubernetes secret accordingly both for pem and pfx certificates.

__**kubernetes.io/dockerconfigjson**__

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

__**kubernetes.io/basic-auth**__

The controller support two formats. Either `username:password` or pre-encoded with base64: `dXNlcm5hbWU6cGFzc3dvcmQ=` stored in a Secret object.

__**kubernetes.io/ssh-auth**__

This must be a properly formatted **Private** SSH Key stored in a Secret object.

## Examples

### Getting a plain secret from Azure Key Vault

```yaml
apiVersion: azure-keyvault-controller.spv.no/v1alpha1
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
  output:
    secret:
      dataKey: azuresecret # key to store object value in kubernetes secret

```

Controller creates:
```yaml
apiVersion: v1
data:
  azuresecret: YXNkZmFzZGZhc2Rm
kind: Secret
metadata:
  name: my-first-azure-keyvault-secret
  namespace: default
type: opaque
```

### Getting a certificate with exportable key from Azure Key Vault

```yaml
apiVersion: azure-keyvault-controller.spv.no/v1alpha1
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
    output:
      secret:
        type: kubernetes/tls
```

Controller creates:
```yaml
apiVersion: v1
data:
  tls.crt: ...
  tls.key: ...
kind: Secret
metadata:
  name: my-first-azure-keyvault-certificate
  namespace: default
type: kubernetes/tls
```
