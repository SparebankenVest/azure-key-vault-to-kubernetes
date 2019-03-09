# Azure Key Vault To Kubernetes

[![Go Report Card](https://goreportcard.com/badge/github.com/SparebankenVest/azure-key-vault-to-kubernetes?style=flat-square)](https://goreportcard.com/report/github.com/SparebankenVest/azure-key-vault-to-kubernetes) [![CircleCI](https://circleci.com/gh/SparebankenVest/azure-key-vault-to-kubernetes.svg?style=shield)](https://circleci.com/gh/SparebankenVest/azure-key-vault-to-kubernetes)

<!-- TOC depthFrom:2 -->

- [Requirements](#requirements)
- [Overview](#overview)
  - [When to use the Controller](#when-to-use-the-controller)
  - [When to use the Env Injector?](#when-to-use-the-env-injector)
  - [Recommendation is to install both](#recommendation-is-to-install-both)
- [How it works](#how-it-works)
  - [Controller](#controller)
  - [Env Injector](#env-injector)
- [Authentication](#authentication)
  - [Override default authentication](#override-default-authentication)
    - [Custom Authentication for the Controller](#custom-authentication-for-the-controller)
    - [Custom Authentication for Env Injector](#custom-authentication-for-env-injector)
    - [Custom Authentication Options](#custom-authentication-options)
- [Authorization](#authorization)
- [Installation](#installation)
  - [Installation without Helm](#installation-without-helm)
- [Usage](#usage)
  - [Vault object types](#vault-object-types)
  - [Commonly used Kubernetes secret types](#commonly-used-kubernetes-secret-types)
- [Examples](#examples)
  - [Plain secret](#plain-secret)
  - [Certificate with exportable key](#certificate-with-exportable-key)
- [Credits](#credits)
- [Contributing](#contributing)

<!-- /TOC -->

## Requirements

* Kubernetes version >= 1.9 
* Default [authentication](#authentication) requires Kubernetes cluster running in Azure - use custom authentication if running outside Azure

## Overview

This project offer two components for handling Azure Key Vault Secrets in Kubernetes:

* Azure Key Vault Controller
* Azure Key Vault Env Injector

The **Azure Key Vault Controller** (Controller for short) is for synchronizing Secrets, Certificates and Keys from Azure Key Vault to native `Secret`'s in Kubernetes.

The **Azure Key Vault Env Injector** (Env Injector for short) is a Kubernetes Mutating Webhook that transparently injects Azure Key Vault secrets as environment variables into programs running in containers, without touching disk or in any other way expose the actual secret content outside the program.

The motivation behind this project was:

1. Avoid a direct program dependency on Azure Key Vault for getting secrets, and adhere to the 12 Factor App principle for configuration (https://12factor.net/config)
2. Make it simple, secure and low risk to transfer Azure Key Vault secrets into Kubernetes as native Kubernetes secrets
3. Securely and transparently be able to inject Azure Key Vault secrets as environment variables to applications, without having to use native Kubernetes secrets

All of these goals are met.

### When to use the Controller 

Use the Controller if:

* the [risks documented with Secrets in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) is acceptable
* there are no concerns about storing Azure Key Vault secrets as base64 encoded plain text values in Kubernetes `Secret` resources
* it is OK that anyone with read access to `Secret` resources in the Kubernetes cluster can read the content of the secrets
* the native `Secret` support in Kubernetes is desired

### When to use the Env Injector? 

Use the Env Injector if:

* any of the [risks documented with Secrets in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) is not acceptable
* there are concerns about storing and exposing base64 encoded Azure Key Vault secrets as Kubernetes `Secret` resources
* preventing Kubernetes users to gain access to Azure Key Vault secret content is important
* the application running in the container support getting secrets as environment variables
* secret environment variable values should not be revealed to Kubernetes resources like Pod specs, stored on disks, visible in logs or exposed in any way other than in-memory for the application 

### Recommendation is to install both

The recommendation is to install both the Controller and the Env Injector, enabling native Kubernetes secrets when needed and transparently injecting environment variables for all other cases.

## How it works

### Controller

The Controller works like this:

By creating a `AzureKeyVaultSecret` resource (a Custom Resource Definition provided by this project) the Controller has everything needed to know which Azure Key Vault and Object it is going to sync.

When created, the Controller kicks in and use the information to download the secret from Azure Key Vault and create a native Kubernetes secret containing the secret from Azure Key Vault.

Periodically the Controller will poll Azure Key Vault for version changes of the secret and apply any changes to the Kubernetes native secret.

See [Usage](#usage) for more details.

**Note-1: Pods in Kubernetes currently do not get notifications when Secret resources change, and Pods will have to be re-created or use something like the Wave controller (https://github.com/pusher/wave) to get the changes**

**Note-2: By default the Controller auto sync secrets every 10 minutes (configurable) and depending on how many secrets are synchronized can cause extra usage costs of Azure Key Vault.**

### Env Injector

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label, like in the example below:

```
apiVersion: v1
kind: Namespace
metadata:
  name: akv-test
  labels:
    azure-key-vault-env-injection: enabled
```

As with the Controller, the Env Injector relies on `AzureKeyVaultSecret` resources to provide information about the Azure Key Vault secrets. 

The Env Injector will start processing containers containing one or more environment placeholders like below: 
```
env:
- name: <name of environment variable>
  value: <name of AzureKeyVaultSecret>@azurekeyvault?<optional field query>
...
```

It will start by injecting a init-container into the Pod. This init-container copies over the `azure-keyvault-env` executable to a share volume between the init-container and the original container. It then changes either the CMD or ENTRYPOINT, depending on which was used by the original container, to use the `azure-keyvault-env` executable instead, and pass on the "old" command as parameters to this new executable. The init-container will then complete and the original container will start.

When the original container starts it will execute the `azure-keyvault-env` command which will download any Azure Key Vault secrets, identified by the environment placeholders above. The remaining step is for `azure-keyvault-env` to execute the original command and params, pass on the updated environment variables with real secret values. This way all secrets gets injected transparently in-memory during container startup, and not reveal any secret content to the container spec, disk or logs.

## Authentication

By default both the Controller and the Env Injector will use the credentials found in Cloud Config on the host to authenticate with Azure Key Vault. This is the same credentials as the Kubernetes cluster use when interacting with Azure to create VM's, Load Balancers and other cloud infrastructure.

**Note: if you do not run Kubernetes on Azure, [override default authentication](#override-default-authentication)**  

Cloud Config for Azure is located at `/etc/kubernetes/azure.json`. The Controller will map this as a read only volume and read the credentials. For the Env Injector it's a bit different. Since the Env Injector is not in full control over how the original container is setup, it will copy the azure.json to a local shared volume, chmod `azure.json` to 444 in case the original container is running under a less privileged user (which is a good practice) and not get access to the credentials.

Currently only one situations has been identified, where the above does not work:

* When a [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is configured in the cluster, preventing containers from reading from the host, two solutions exists:  
  1. Change the Pod Security Policy to list `/etc/kubernetes/azure.json` under [AllowedHostPaths](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) 
  2. Or [override default authentication](#override-default-authentication). 

**For default authentication move to the next section about [Authorization](#authorization). To override default authentication, read on.**

### Override default authentication

It is possible to give the Controller and/or the Env Injector specific credentials to authenticate with Azure Key Vault.

The authentication requirements for the Controller and Env Injector are covered below.

#### Custom Authentication for the Controller 

The Controller will need Azure Key Vault credentials to get Secrets from Azure Key Vault and store them as Kubernetes Secrets. See [Authentication options](#authentication-options) below.

#### Custom Authentication for Env Injector

To use custom authentication for the Env Injector, set  the environment variable `CUSTOM_AUTH` to `true`.

By default each Pod using the Env Injector pattern must provide their own credentials for Azure Key Vault using [Authentication options](#authentication-options) below.

To avoid that, support for a more convenient solution is added where the Azure Key Vault credentials in the Env Injector (using [Authentication options](#authentication-options) below) is "forwarded" to the the Pods. This is enabled by setting the environment variable `CUSTOM_AUTH_INJECT` to `true`. Env Injector will then create a Kubernetes Secret containing the credentials and modify the Pod's env section to reference the credentials in the Secret. 

#### Custom Authentication Options

The following authentication options are available:

| Authentication type |	Environment variable |	Description |
| ------------------- | -------------------- | ------------ |
| Managed identities for Azure resources (used to be MSI) | | No credentials are needed for managed identity authentication. The Kubernetes cluster must be running in Azure and the `aad-pod-identity` controller must be installed. A `AzureIdentity` and `AzureIdentityBinding` must be defined. See https://github.com/Azure/aad-pod-identity for details. |
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

**Note: These env variables are sensitive and should be stored in a Kubernetes `Secret` resource, then referenced by [Using Secrets as Environment Variables](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables).** 

See official MS documentation for more details on how environment base authentication works for Azure: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication

## Authorization

No matter which authentication option is used, the authenticated account will need `get` permissions to the different object types in Azure Key Vault.

**Note: It's only possible to control access at the top level of Azure Key Vault, not per object/resource. The recommendation is therefore to have a dedicated Key Vault per cluster.**

Access is controlled through Azure Key Vault policies and can be configured through Azure CLI like this:

Azure Key Vault Secrets:

`az keyvault set-policy -n <azure key vault name> --secret-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Certificates:

`az keyvault set-policy -n <azure key vault name> --certificate-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Keys:

`az keyvault set-policy -n <azure key vault name> --key-permissions get --spn <service principal id> --subscription <azure subscription>`

## Installation

It's recommended to use Helm charts for installation:

Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller

Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector

### Installation without Helm

If Helm is not an option, use Helm on a local computer to generate the Kubernetes templates like below:

`helm install --debug --dry-run <options>`

See the individual Helm charts for `<options>`.

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
      contentType: <only used when type is the special multi-key-value-secret - either application/x-json or application/x-yaml>
  output: # ignored by env injector, required by controller to output kubernetes secret
    secret: 
      name: <name of the kubernetes secret to create>
      dataKey: <required when type is opaque - name of the kubernetes secret data key to assign value to - ignored for all other types>
      type: <optional - kubernetes secret type - defaults to opaque>
```

See [Examples](#examples) for different usages.

### Vault object types

| Object type   | Description |
| ------------- | ----------- |
| `secret`      | Azure Key Vault Secret - can contain any secret data |
| `certificate` | Azure Key Vault Certificate - A TLS certificate with just the public key or both public and private key if exportable |
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
  output:
    secret:
      name: keyvault-secret
      dataKey: azuresecret # key to store object value in kubernetes secret

```

If Controller is installed the following Kubernetes Secret will be created:

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
  output:
    secret:
      name: keyvault-certificate
      type: kubernetes/tls
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
type: kubernetes/tls
```

Note that since `spec.output.secret.type=kubernetes/tls` a Kubernetes Secret of type `kubernetes/tls` was created.

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

## Credits

Credit goes to Banzai Cloud for coming up with the [original idea](https://banzaicloud.com/blog/inject-secrets-into-pods-vault/) of environment injection for their [bank-vaults](https://github.com/banzaicloud/bank-vaults) solution, which they use to inject Hashicorp Vault secrets into Pods.

## Contributing

Development of Azure Key Vault for Kubernetes happens in the open on GitHub, and encourage users to:

* Send a pull request with any security issues found and fixed
* Send a pull request with your new features and bug fixes
* Report issues on security or other issues you have come across
* Help new users with issues they may encounter
* Support the development of this project and star this repo!

**[Code of Conduct](CODE_OF_CONDUCT.md)**

Sparebanken Vest has adopted a Code of Conduct that we expect project participants to adhere to. Please read the full text so that you can understand what actions will and will not be tolerated.

**[License](LICENSE)**

Azure Key Vault to Kubernetes is licensed under Apache License 2.0.