# Azure Key Vault To Kubernetes

[![Go Report Card](https://goreportcard.com/badge/github.com/SparebankenVest/azure-key-vault-to-kubernetes?style=flat-square)](https://goreportcard.com/report/github.com/SparebankenVest/azure-key-vault-to-kubernetes)
[![CircleCI](https://circleci.com/gh/SparebankenVest/azure-key-vault-to-kubernetes.svg?style=shield)](https://circleci.com/gh/SparebankenVest/azure-key-vault-to-kubernetes)

**This project is currently in Alpha and not yet ready for public consumption**

A Kubernetes controller synchronizing Secrets, Certificates and Keys from Azure Key Vault to `Secret`'s in Kubernetes (Basic mode)...

...and/or a Kubernetes Mutating Web Hook that transparently injects Azure Key Vault secrets into containers (transparent mode).

<!-- TOC depthFrom:2 -->

- [How it works](#how-it-works)
  - [Basic mode](#basic-mode)
  - [Transparant mode](#transparant-mode)
- [Authentication](#authentication)
  - [Basic mode](#basic-mode-1)
  - [Transparant mode](#transparant-mode-1)
  - [Authentication options](#authentication-options)
- [Authorization](#authorization)
- [Installation](#installation)
  - [Basic mode](#basic-mode-2)
  - [Transparant mode](#transparant-mode-2)
- [Usage](#usage)
  - [Vault object types](#vault-object-types)
  - [Commonly used Kubernetes secret types](#commonly-used-kubernetes-secret-types)
- [Examples](#examples)
  - [Plain secret (Basic)](#plain-secret-basic)
  - [Certificate with exportable key (Basic)](#certificate-with-exportable-key-basic)
  - [Plain secret (Transparant)](#plain-secret-transparant)
  - [Certificate with exportable key (Transparant)](#certificate-with-exportable-key-transparant)

<!-- /TOC -->

## How it works

Azure Key Vault To Kubernetes works in two different modes:

1) Basic - Sync objects from Azure Key Vault to `Secret` resources in Kubernetes
2) Transparant - Synch objects from Azure Key Vault and inject them as environment variables transparantly into containers 

### Basic mode

The Basic mode is the most straight forward option, but also the least secure as it stores Azure Key Vault objects as Secrets in Kubernetes which is base64 encoded in plain text. For many scenarios that is OK, but in the banking world were this project originated, that is not an option (see [Transparant mode](#transparant-mode) below).

The same [risks as documented with `Secret`'s in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) also apply for the Basic mode, with the exception of secrets being checked into source control or unintentionally exposed by other means, which the `AzureKeyVaultSecret` resource prevents.

Make sure you fully understand these risks before synchronizing any Azure Key Vault secrets to Kubernetes usint the Basic mode.

The Basic mode works like this:

1. Create a `AzureKeyVaultSecret` resource containing information of how to get a secret from Azure Key Vault
2. The `azure-keyvault-controller` controller discovers the newly created `AzureKeyVaultSecret` and use its information to get the secret from Azure Key Vault to create a Kubernetes `Secret`
3. The `azure-keyvault-controller` controller will periodically poll Azure Key Vault for changes and apply any changes to the Kubernetes `Secret`s.

**Note: By default the `azure-keyvault-controller` controller auto synch Secrets every 10 minutes ([artifacts/example-controller-deployment.yaml](artifacts/example-controller-deployment.yaml)) and depending on how many secrets are synchronized can cause extra usage costs of Azure Key Vault.**

### Transparant mode

The Transparant mode is the most secure option, as it transparantly injects Azure Key Vault objects as environment variables into containers, without touching disk or making values visible in container specs.

The transparant mode works like this:

1. Create a `AzureKeyVaultSecret` resource containing information of how to get a secret from Azure Key Vault
2. Define a Pod (typically using `Deployment` or anything else that creates a Pod in Kuberntes) and define environment variable placeholders like this:
```
env:
- name: SECRET1
  value: azurekeyvault#<name of AzureKeyVaultSecret>
- name: SECRET2
  value: azurekeyvault#<name of AzureKeyVaultSecret>
...
```
3. When the pod is about to be created, a Mutating Web Hook downloads all referenced secrets from Azure Key Vault and inject them as environment variables to the executable running in the container (not to the pod itself, since that would reveal the secret in the pod spec) 

## Authentication

The `azure-keyvault-controller` use environment-based authentication as documented here: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication

To avoid exposing Azure Key Vault credentials in Kubernetes (like in a `Secret`) the recommendation is to take advantage of Azure Managed Service Identity (MSI) in Kubernetes by using [`azure-pod-identity`](https://github.com/Azure/aad-pod-identity).

Which components require authentication will depend on which mode you run `azure-key-vault-to-kubernetes` in.

### Basic mode

In Basic mode the `azure-keyvault-controller` will need Azure Key Vault credentials to get Secrets from Azure Key Vault and store them as Kubernetes Secrets. If the Kubernetes cluster is utilizing Manages Service Identity through `azure-pod-identity` the controller just needs the proper label to pick up the credentials. If not, see [Authentication options](#authentication-options) below.

### Transparant mode

In Transparant mode every container referencing `azurekeyvault` environment values needs to have access to Azure Key Vault credentials. If the Kubernetes cluster is utilizing Manages Service Identity through `azure-pod-identity`, the container just needs the proper label to pick up the credentials. If not, see [Authentication options](#authentication-options) below.

### Authentication options
At the time of writing the following authentication options was available (extracted from here: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication):

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

## Authorization

The account configured under Authentication will need `get` permissions to the object types (secret, certificate and key) in Azure Key Vault to synchronize with Kubernetes.

**Note: It's only possible to control access on the top level of Azure Key Vault, not per object/resource. The recommedation is therefore to have a dedicated Key Vault per cluster.**

Access is controlled through Azure Key Vault policies and can be configured through Azure CLI like this:

Azure Key Vault Secrets:

`az keyvault set-policy -n <azure key vault name> --secret-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Certificates:

`az keyvault set-policy -n <azure key vault name> --certificate-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Keys:

`az keyvault set-policy -n <azure key vault name> --key-permissions get --spn <service principal id> --subscription <azure subscription>`

## Installation

It's recommended to use the Helm chart [https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-to-kubernetes](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-to-kubernetes) for installation, but a manual option is also available and described below.

### Basic mode

**1. Deploy the Custom Resource Definition for AzureKeyVaultSecret**

The CRD can be found here: [artifacts/crd.yaml](artifacts/crd.yaml)

**2. Deploy the RBAC defininition**

The RBAC can be found here: [artifacts/controller-rbac.yaml](artifacts/controller-rbac.yaml)

**3. Deploy controller**

An example deployment definition can be found here: [artifacts/example-controller-deployment.yaml](artifacts/example-controller-deployment.yaml)

Optional environment variables:

| Env var                              | Description | Default |
| ------------------------------------ | ----------- | ------- |
| AZURE_VAULT_NORMAL_POLL_INTERVALS    | Duration to wait between polls to Azure Key Vault for changes | 1m |
| AZURE_VAULT_EXCEPTION_POLL_INTERVALS | Duration to wait between polls to Azure Key Vault for changes, after AZURE_VAULT_MAX_FAILURE_ATTEMPTS is reached | 5m |
| AZURE_VAULT_MAX_FAILURE_ATTEMPTS     | How many failures are accepted before reducing the frequency to Slow | "5" |
| LOG_LEVEL                            | Log level to use for output logs. Options are `trace`, `debug`, `info`, `warning`, `error`, `fatal` or `panic`. | info |

In addition there are environment variables for controlling authentication which is [documented above](#authentication-options).

### Transparant mode

The Transparant mode requires everything in Basic mode, plus:

**4. TBD**

## Usage
After you have installed `azure-key-vault-to-kubernetes`, you can create `AzureKeyVaultSecret` resources and take advantage of either Kubernetes Secrets (Basic) or referencing `AzureKeyVaultSecret` resources from Pods.

**NB! `output` is only used in Basic mode - the controller wil create the Azure Key Vault secret as a Kubernetes Secret - in Transparant mode `output` must be undefined.**

The `AzureKeyVaultSecret` is defined using this schema:

```yaml
apiVersion: spv.no/v1alpha1
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
    secret: # required for Basic mode (output is Kubernetes Secret)
      name: <required - name of the kubernetes secret to create - defaults to this resource metadata.name>
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
| `multi-key-value-secret`  | A special kind of Azure Key Vault Secret only understood by the controller - For cases where the Secret contains `json` or `yaml` key/value items that will be directly exported as key/value items in the Kubernetes secret. When `multi-key-value-secret` type is used, the `contentType` property MUST also be set to either `application/x-json` or `application/x-yaml`. |

### Commonly used Kubernetes secret types

For a complete list: https://github.com/kubernetes/api/blob/49be0e3344fe443eb3d23105225ed2f1ab1e6cab/core/v1/types.go#L4950

| Secret type                      | Keys |
| -------------------------------- | ---- |
| `opaque` (default)               | defined in `spec.output.secret.dataKey` |
| `kubernetes.io/tls`              | `tls.key`, `tls.crt` |
| `kubernetes.io/dockerconfigjson` | `.dockerconfigjson` |
| `kubernetes.io/dockercfg`        | `.dockercfg` |
| `kubernetes.io/basic-auth`       | `username`, `password` |
| `kubernetes.io/ssh-auth`         | `ssh-privatekey` |


With the exception of the `opaque` secret type, the controller will make a best effort to export the Azure Key Vault object into the secret type defined.

**kubernetes/tls**

By pointing to a **exportable** Certificate object in Azure Key Vault AND setting the Kubernetes output secret type to `kubernetes/tls`, the controller will automatically format the Kubernetes secret accordingly both for pem and pfx certificates.

__kubernetes.io/dockerconfigjson__

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

__kubernetes.io/basic-auth__

The controller support two formats. Either `username:password` or pre-encoded with base64: `dXNlcm5hbWU6cGFzc3dvcmQ=` stored in a Secret object.

__kubernetes.io/ssh-auth__

This must be a properly formatted **Private** SSH Key stored in a Secret object.

## Examples

### Plain secret (Basic)

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

### Certificate with exportable key (Basic)

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

### Plain secret (Transparant)

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
  output:
    secret:
      dataKey: azuresecret # key to store object value in kubernetes secret

```

Container reference:
```yaml
...
containers:
- name: alpine
  env:
  - name: MY_SECRET
    value: azurekeyvault@my-first-azure-keyvault-secret
...
```

### Certificate with exportable key (Transparant)

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
```

Container reference:

```yaml
...
containers:
- name: alpine
  env:
  - name: PUB_KEY
    value: azurekeyvault@my-first-azure-keyvault-certificate?tls.crt
  - name: PRIV_KEY
    value: azurekeyvault@my-first-azure-keyvault-certificate?tls.key
...
```