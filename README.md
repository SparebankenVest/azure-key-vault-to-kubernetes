# azure-keyvault-controller

A Kubernetes controller and a Custom Resource that together will allow you to sync objects from Azure Key Vault to `Secret`'s in Kubernetes.

## Understand this!

The same [risks as documented with `Secret`'s in Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/#risks) also apply for the `azure-keyvault-controller`, with the exception of:

_... If you configure the secret through a manifest (JSON or YAML) file which has the secret data encoded as base64, sharing this file or checking it in to a source repository means the secret is compromised. Base64 encoding is not an encryption method and is considered the same as plain text. ..._

**One of the main reasons for creating this controller was to mitigate the risk above. Using the `azure-keyvault-controller` and the `AzureKeyVaultSecret` resource is a nice way of preventing secrets from being checked into source control or unintentionally be exposed by other means.**

Make sure you fully understand these risks before synchronizing any Azure Key Vault secrets to Kubernetes.

## How it works

When the `azure-keyvault-controller` is running in your Kubernetes cluster, you can define one or more `AzureKeyVaultSecret` resources that will be picked up by the controller and synchronized into Kubernetes `Secret`'s.

Note: this on only possible if the Azure credentials which `azure-keyvault-controller` is running under has access to the Azure Key Vault defined in the `AzureKeyVaultSecret`.

The `AzureKeyVaultSecret` has one section for Azure Key Vault and another for the Kubernetes `Secret` to output (see complete example under Usage below):

```yaml
vault:
  name: <name of azure key vault>
  objectType: <object type in azure key vault to sync> # options are secret, certificate or key
  objectName: <name of azure key vault object to sync>
outputSecret:
  name: <name of the kubernetes secret to create>
  keyName: <name of kubernetes secret key to assing secret value to> # currently limited to just one key
  type: <kubernetes secret type> # Optional. Default Opaque. See Kubernetes Secret docs for options.
```

## Authentication

The `azure-keyvault-controller` use environment-based authentication as documented here: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication

Note: If you plan to use Managed Service Identity (MSI) you will need to have the [`azure-pod-identity`](https://github.com/Azure/aad-pod-identity) running and configured in the cluster. You will need the `azure-pod-identity` controller, define a `AzureIdentity` AND use the `aadpodidbinding` label with the right selector for your Pod/Deployment.

## Azure Key Vault Authorization

The account which the controller is running under must also have Azure Key Vault `get` permissions to the different object types that will be synchronized to Kubernetes. This is controlled through Azure Key Vault policies and can be configured through Azure CLI like this:

Azure Key Vault Secrets:

`az keyvault set-policy -n <azure key vault name> --secret-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Certificates:

`az keyvault set-policy -n <azure key vault name> --certificate-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Keys:

`az keyvault set-policy -n <azure key vault name> --key-permissions get --spn <service principal id> --subscription <azure subscription>`

Azure Key Vault Storage (beta):

`az keyvault set-policy -n <azure key vault name> --storage-permissions get --spn <service principal id> --subscription <azure subscription>`

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

In addition there are environment variables for controlling **Azure authentication** which is documented by Microsoft here: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication

At the time of writing the following options was available:

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
    objectType: secret
    objectName: test
  outputSecret:
    name: my-kubernetes-azure-secret
    keyName: value
    type: Opaque # Optional. Default Opaque. For options, see Kubernetes Secrets docs
```
