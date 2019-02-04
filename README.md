# Azure Key Vault Secrets for Kubernetes

A Kubernetes controller synchronizing Secrets, Certificates and Keys from Azure Key Vault to `Secret`'s in Kubernetes.

**Problem:** "I have to manually extract secrets from Azure Key Vault and apply them as Secrets in Kubernetes."

**Solution:** "Install the `azure-keyvault-controller` and automatically synchronize objects from Azure Key Vault as secrets in Kubernetes."

## Understand this!

The same [risks as documented with `Secret`'s in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) also apply for the `azure-keyvault-controller`, with the exception of:

_... If you configure the secret through a manifest (JSON or YAML) file which has the secret data encoded as base64, sharing this file or checking it in to a source repository means the secret is compromised. Base64 encoding is not an encryption method and is considered the same as plain text. ..._

**One of the main reasons for creating this controller was to mitigate the risk above. Using the `azure-keyvault-controller` and the `AzureKeyVaultSecret` prevent secrets from being checked into source control or unintentionally be exposed by other means.**

Make sure you fully understand these risks before synchronizing any Azure Key Vault secrets to Kubernetes.

## How it works

Using the custom `AzureKeyVaultSecret` Kubernetes resource the `azure-keyvault-controller` will synchronize Azure Key Vault objects (secrets, certificates and keys) into Kubernetes `Secret`'s.

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
      type: <object type in azure key vault to sync> # options are secret, certificate or key
      version: <version of object to sync> # optional
  output:
    secret:
      name: <name of the kubernetes secret to create> # optional - if not set, name of this resource will be used (metadata.name)
      dataKey: <name of the kubernetes secret data key to assign value to>
      type: <kubernetes secret type> # optional - default Opaque - see Kubernetes Secret docs for options
```

After this resource is applied to Kubernetes, the controller will try to retreive the specified object from Azure Key Vault and apply it as a Kubernetes `secret`. Later the controller will periodically poll Azure Key Vault to check if the object has changed, and if so apply the change to the Kubernetes `secret`.

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

#### 1. Deploy the Custom Resource Definition for AzureKeyVaultSecret

The CRD can be found here: [artifacts/crd.yaml](artifacts/crd.yaml)

#### 2. Deploy controller

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

After you have installed the `azure-keyvault-controller`, you can create `AzureKeyVaultSecret` resources. Example:

```yaml
apiVersion: azure-keyvault-controller.spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: my-first-azure-keyvault-secret
  namespace: default
spec:
  vault:
    name: my-kv
    object:
      type: secret
      name: test
      version: c1f64e6a55224ccc88f85d4162a7a66b # optional - will use latest object version by default
  output:
    secret:
      name: my-kubernetes-azure-secret # optional - defaults to name of this resource (metadata.name)
      dataKey: value
      type: opaque # optional - default opaque - for options, see kubernetes secrets docs
```
