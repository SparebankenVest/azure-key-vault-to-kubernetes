# Azure Key Vault To Kubernetes

[![Release](https://img.shields.io/github/release/atrox/sync-dotenv.svg?style=flat-square)](https://github.com/SparebankenVest/azure-key-vault-to-kubernetes/releases/latest)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FSparebankenVest%2Fazure-key-vault-to-kubernetes%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/SparebankenVest/azure-key-vault-to-kubernetes/goto?ref=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/SparebankenVest/azure-key-vault-to-kubernetes?style=flat-square)](https://goreportcard.com/report/github.com/SparebankenVest/azure-key-vault-to-kubernetes) 

Project status: Stable - multipal financial institutions are running this project on production Kubernetes clusters

Read the announcement: https://mrdevops.io/introducing-azure-key-vault-to-kubernetes-931f82364354

<!-- TOC depthFrom:2 -->

- [Installation](#installation)
  - [Installation without Helm](#installation-without-helm)
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
- [Usage](#usage)
  - [The AzureKeyVaultSecret resource](#the-azurekeyvaultsecret-resource)
    - [Vault object types](#vault-object-types)
  - [The Controller](#the-controller)
    - [Commonly used Kubernetes secret types](#commonly-used-kubernetes-secret-types)
  - [The Env Injector](#the-env-injector)
    - [Using queries with the Env Injector](#using-queries-with-the-env-injector)
  - [Azure Key Vault Secrets with `kubectl`](#azure-key-vault-secrets-with-kubectl)
- [Examples](#examples)
  - [Plain secret](#plain-secret)
  - [Certificate with exportable key](#certificate-with-exportable-key)
- [Known issues](#known-issues)
  - [Env Injector - x509: certificate signed by unknown authority](#env-injector---x509-certificate-signed-by-unknown-authority)
- [Troubleshooting](#troubleshooting)
  - [Where can I find logs and look for errors?](#where-can-i-find-logs-and-look-for-errors)
  - [](#)
- [Credits](#credits)
- [Contributing](#contributing)

<!-- /TOC -->

## Installation

It's recommended to use Helm charts for installation:

Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller

Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector

### Installation without Helm

If Helm is not an option in Kubernetes, use Helm on a local computer to generate the Kubernetes templates like below:

`helm install --debug --dry-run <options>`

See the individual Helm charts above for `<options>`.

## Requirements

* Kubernetes version >= 1.9 
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
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

### Env Injector

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. As with the Controller, the Env Injector relies on `AzureKeyVaultSecret` resources to provide information about the Azure Key Vault secrets. 

The Env Injector will start processing containers containing one or more environment placeholders like below: 
```
env:
- name: <name of environment variable>
  value: <name of AzureKeyVaultSecret>@azurekeyvault?<optional field query>
...
```

**Note: To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label**

It will start by injecting a init-container into the Pod. This init-container copies over the `azure-keyvault-env` executable to a share volume between the init-container and the original container. It then changes either the CMD or ENTRYPOINT, depending on which was used by the original container, to use the `azure-keyvault-env` executable instead, and pass on the "old" command as parameters to this new executable. The init-container will then complete and the original container will start.

When the original container starts it will execute the `azure-keyvault-env` command which will download any Azure Key Vault secrets, identified by the environment placeholders above. The remaining step is for `azure-keyvault-env` to execute the original command and params, pass on the updated environment variables with real secret values. This way all secrets gets injected transparently in-memory during container startup, and not reveal any secret content to the container spec, disk or logs.

See [Usage](#usage) for more details.

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

**Note: The Env Injector needs to be anabled for each namespace**

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label, like in the example below:

```
apiVersion: v1
kind: Namespace
metadata:
  name: akv-test
  labels:
    azure-key-vault-env-injection: enabled
```

## Usage

### The AzureKeyVaultSecret resource

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

**Note - the `output` is only used by the Controller to create the Azure Key Vault secret as a Kubernetes native Secret - it is ignored and not needed by the Env Injector.**

#### Vault object types

| Object type   | Description |
| ------------- | ----------- |
| `secret`      | Azure Key Vault Secret - can contain any secret data |
| `certificate` | Azure Key Vault Certificate - A TLS certificate with just the public key or both public and private key if exportable |
| `key`         | Azure Key Vault Key - A RSA or EC key used for signing |
| `multi-key-value-secret`  | A special kind of Azure Key Vault Secret only understood by the Controller and the Env Injector. For cases where a secret contains `json` or `yaml` key/value items that will be directly exported as key/value items in the Kubernetes secret, or access with queries in the Evn Injector. When `multi-key-value-secret` type is used, the `contentType` property MUST also be set to either `application/x-json` or `application/x-yaml`. |

See [Examples](#examples) for different usages.

### The Controller

Make sure the Controller is installed in the Kubernetes cluster, then:

Create `AzureKeyVaultSecret` resources to synchronize into native Kubernetes secrets. Note that the `output` section is mandatory:

```yaml
  output: 
    secret: 
      name: <required - name of the kubernetes secret to create>
      dataKey: <required when type is opaque - name of the kubernetes secret data key to assign value to - ignored for all other types>
      type: <optional - kubernetes secret type - defaults to opaque>
```

Azure certificates can be exported to multiple types. The preferred output type is `kubernetes.io/tls`, but this is not always suitable for the consuming application. If the type is set to `opaque` it will output the raw certificate into the specified dataKey. If type is not specified (left blank), it will export the certificate in pem, unless the dataKey has the suffix `.key`. In the latter case, it will export the private key as pem.

**Note-1: Pods in Kubernetes currently do not get notifications when Secret resources change, and Pods will have to be re-created or use something like the Wave controller (https://github.com/pusher/wave) to get the changes**

**Note-2: By default the Controller auto sync secrets every 10 minutes (configurable) and depending on how many secrets are synchronized can cause extra usage costs of Azure Key Vault.**

#### Commonly used Kubernetes secret types

The default secret type (`spec.output.secret.type`) is `opaque`. Below is a list of supported Kubernetes secret types and which keys each secret type stores.

For a complete list: https://github.com/kubernetes/api/blob/49be0e3344fe443eb3d23105225ed2f1ab1e6cab/core/v1/types.go#L4950

| Secret type                      | Keys |
| -------------------------------- | ---- |
| `opaque` (default)               | defined in `spec.output.secret.dataKey` |
| `kubernetes.io/tls`              | `tls.key`, `tls.crt` |
| `kubernetes.io/dockerconfigjson` | `.dockerconfigjson` |
| `kubernetes.io/dockercfg`        | `.dockercfg` |
| `kubernetes.io/basic-auth`       | `username`, `password` |
| `kubernetes.io/ssh-auth`         | `ssh-privatekey` |


With the exception of the `opaque` secret type, the Controller will make a best effort to export the Azure Key Vault object into the secret type defined.

**kubernetes.io/tls**

By pointing to a **exportable** Certificate object in Azure Key Vault AND setting the Kubernetes output secret type to `kubernetes.io/tls`, the controller will automatically format the Kubernetes secret accordingly both for pem and pfx certificates.

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

### The Env Injector

Make sure the Env Injector is installed in the Kubernetes cluster, then:

1. Set the `azure-key-vault-env-injection` label for the namespace(s) where the secret is going to be used
2. Create `AzureKeyVaultSecret` resources references secrets in Azure Key Vault
3. Inject into applications using syntax below, referencing to the `AzureKeyVaultSecret` in 2.

```yaml
env:
- name: <name of environment variable>
  value: <name of AzureKeyVaultSecret>@azurekeyvault?<optional field query>
...
```

**Example:**

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: default
  labels:
    azure-key-vault-env-injection: enabled
```

```yaml 
# my-azure-keyvault-secret.yaml
apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: my-azure-keyvault-secret
  namespace: default
spec:
  vault:
    name: my-kv # name of key vault
    object:
      type: secret # object type
      name: test-secret # name of the object
```

```yaml
# my-deployment.yaml
...
env:
- name: MY_SECRET
  value: my-azure-keyvault-secret@azurekeyvault
...
```

Apply the resources to Kubernetes:

```bash
kubectl apply -f namespace.yaml
kubectl apply -f my-azure-keyvault-secret.yaml
kubectl apply -f my-deployment.yaml
```

**Note: For the Env Injector, the `output` section of the `AzureKeyVaultSecret` is ignored, but if `output` is provided AND the Controller is also installed, it WILL create a Kubernetes secret, which is probably not the intention when using the Env Injector.**

#### Using queries with the Env Injector

The syntax used with environment variables for the Env Injector is:

`<name of AzureKeyVaultSecret>@azurekeyvault?<optional field query>`

There is currently only two cases where using a query is valid:

1. For the Azure Key Vault type `certificate`
2. For the special Env Injector/Azure Key Vault type `multi-key-value-secret` 

For `certificate`, the available keys to query are `tls.key` (private key) and `tls.crt` (public key).

The `multi-key-value-secret` is either a json or yaml document, containing `<key>: <value>` (yaml) or `"<key>": "<value>"` (json) elements only. See [Vault object types](#vault-object-types) for details. Only top level key/value is supported. Here is an example to illustrate:

yaml:
```yaml
key1: my key 1 value
key2: my key 2 value
```

json:
```yaml
{
  "key1": "my key 1 value",
  "key2": "my key 2 value"
}
```

To get `key2` using query:

`xxx@azurekeyvault?key2` which will return `my key 2 value`.

### Azure Key Vault Secrets with `kubectl`

List Azure Key Vault Secrets in namespace:
```
$ kubectl -n default get akvs
NAME       VAULT         VAULT OBJECT   SECRET NAME   SYNCHED
secret-1   my-kv         Secret1                 
secret-2   my-other-kv   Secret2                        
secret-3   my-kv         Secret3        my-secret-3   2019-11-30T06:09:05Z
secret-4   my-other-kv   Secret4        my-secret-4   2019-11-30T06:09:35Z
```

List all Azure Key Vault Secrets in cluster:
```
$ kubectl get akvs --all-namespaces
```

Inspect individual secrets:
```
$ kubectl -n default describe akvs my-secret
```

Check events:
```
$ kubectl -n default get events
LAST SEEN   TYPE     REASON        OBJECT                                      MESSAGE
4m40s       Normal   Synced        azurekeyvaultsecret/my-credentials          AzureKeyVaultSecret synced successfully
4m40s       Normal   Synced        azurekeyvaultsecret/my-cert                 AzureKeyVaultSecret synced successfully
```

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

## Known issues

### Env Injector - x509: certificate signed by unknown authority

**Issue:** Trying to inject secrets into a application running on a container without CA certificates will fail with an error like below:

`level=fatal msg="env-injector: failed to read secret 'test', error azure.BearerAuthorizer#WithAuthorization: Failed to refresh the Token for request to https://my-key-vault.vault.azure.net/secrets/test/?api-version=2016-10-01: StatusCode=0 -- Original Error: adal: Failed to execute the refresh request. Error = 'Post https://login.microsoftonline.com/xxx/oauth2/token?api-version=1.0: x509: certificate signed by unknown authority'"`

Doing HTTPS calls without CA certificates will make it impossible for the client to validate if a TLS certificate is signed by a trusted CA. 

**Solution:** Make sure CA certificates are installed in the Docker image used by the container you are trying to inject env vars into (eg. `apt-get install -y ca-certificates`)

## Troubleshooting

### Where can I find logs and look for errors?

Both the controller and the env-injector output logs, so use `kubectl logs` for inspection. There are also some events beeing written to Kubernetes, which can be viewed using `kubectl get events`.

### 

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
