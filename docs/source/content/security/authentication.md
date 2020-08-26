---
title: "Authentication"
description: "Learn about the different options for authenticating with Azure Key Vault."
---

By default both the Controller and the Env Injector will assume it is running on Azure (since Azure Key Vault is most commonly used in Azure) - and use the default AKS service principal for authentication - unless custom authentication is provided (see [Custom Authentication](#custom-authentication) below). 

Default authentication is the AKS credentials that are available on all Nodes (hosts) at `/etc/kubernetes/azure.json`. These credentials are the same as the Kubernetes cluster use when interacting with Azure to create VM's, Load Balancers and other cloud infrastructure. 

> **Note: The preferred solution would be to use [Azure Managed Identities](https://docs.microsoft.com/en-us/azure/aks/use-managed-identity), but this is still in preview - so for now we rely on the default AKS service principal.**

## Situations where Default Authentication does not Work

Currently only one situations has been identified, where default authentication does not work inside Azure.

**When a [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is configured in the cluster, preventing containers from reading from the host.**

Two solutions exists:  
  1. Change the Pod Security Policy to list `/etc/kubernetes/azure.json` under [AllowedHostPaths](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) 
  2. Or [use custom authentication](#custom-authentication). 

## Custom Authentication

It is possible to give the Controller and/or the Env Injector specific credentials to authenticate with Azure Key Vault. The authentication requirements for the Controller and Env Injector are covered below.

## Custom Authentication for the Controller 

The Controller will need Azure Key Vault credentials to get Secrets from Azure Key Vault and store them as Kubernetes Secrets. In order to provide custom credentials, pass inn the value `keyVault.customAuth.enabled=true` to the Controller Helm Chart together with one of the [Authentication options](#custom-authentication-options) described below.

Fore more details, see the [Controller Helm Chart](/stable/azure-key-vault-controller/README/#installing-the-chart).

## Custom Authentication for the Env Injector

The Env-Injector execute locally inside your Pod and needs access to Azure Key Vault credentials to inject secrets. Two options are available:

1) The Env-Injector running inside the container request credentials from the Env-Injector authentication service (default / centralized)
2) The Pod hosting the container provide credentials to the Env-Injector running inside the container (custom authentication / local)

For option 1 you only provide credentials when installation of the Env-Injector.

For option 2 you provide credentials to every Pod that will use the Env-Injector.

Option 1 is easiest and most convenient, but will give the same credentials to all Pods using Env-Injector. 

**Recommendations:**

|                                                      | Env-Injector Auth Service | Credentials in Pod |
| ---------------------------------------------------- | :-----------------------: | :---------------------------: |
| Using one Azure Key Vault per cluster                | &#10004;                  |                               |
| Using multiple Azure Key Vaults per cluster (f.ex. one Key Vault per application) and it is OK to use the same credentials to all Key Vaults | &#10004;                  |                               |
| Multi-tenant environment (multiple Azure Key Vaults) |                           | &#10004;                      |


|                                                      | Env-Injector Auth Service | Credentials in Pod |
| ---------------------------------------------------- | :-----------------------: | :---------------------------: |
| Provide credentials only during Env-Injector install | &#10004;
| Must provide credentials to every Pod when using Env-Injector | | &#10004;|
| The same Azure Key Vault credentials used in all Pods using Env-Injector | &#10004; ||
| Recommended if there is one Azure Key Vault per cluster | &#10004; | |

To use custom authentication for the Env Injector there are three options:

1. Use Microsft's [AAD Pod Identity](https://github.com/Azure/aad-pod-identity) (see [Using Custom Authentication with AAD Pod Identity](/stable/azure-key-vault-env-injector/README/#using-custom-authentication-with-aad-pod-identity))
2. Use custom credentials through credential injection (see [Using Custom Authentication with Credential Injection Enabled](/stable/azure-key-vault-env-injector/README/#using-custom-authentication-with-credential-injection-enabled))
3. Provide credentials for each Pod using the Env Injector pattern using [Authentication options](#custom-authentication-options) below.

To avoid using option no. 3, support for a more convenient solution (no. 2) is supported where the Azure Key Vault credentials in the Env Injector (using [Authentication options](#custom-authentication-options) below) is "forwarded" to the the Pods. The Env Injector will create a Kubernetes Secret containing the credentials and mutate the Pod's env section to reference the credentials in the Secret. 

Fore more details, see the [Env Injector Helm Chart](/stable/azure-key-vault-env-injector/README/#installing-the-chart).

## Custom Authentication Options

The following authentication options are available:

| Authentication type |	Environment variable         | Description |
| ------------------- | ---------------------------- | ------------ |
| Managed identities for Azure resources (used to be MSI) | | No credentials are needed for managed identity authentication. The Kubernetes cluster must be running in Azure and the `aad-pod-identity` controller must be installed. A `AzureIdentity` and `AzureIdentityBinding` must be defined. See https://github.com/Azure/aad-pod-identity for details. |
| Client credentials 	| `AZURE_TENANT_ID` 	         | The ID for the Active Directory tenant that the service principal belongs to. |
|                     |	`AZURE_CLIENT_ID` 	         | The name or ID of the service principal. |
|                     |	`AZURE_CLIENT_SECRET`        | The secret associated with the service principal. |
| Certificate 	      | `AZURE_TENANT_ID`            | The ID for the Active Directory tenant that the certificate is registered with. |
|                     | `AZURE_CLIENT_ID`            | The application client ID associated with the certificate. |
|                     | `AZURE_CERTIFICATE_PATH`     | The path to the client certificate file. |
|                     | `AZURE_CERTIFICATE_PASSWORD` | The password for the client certificate. |
| Username/Password   | `AZURE_TENANT_ID`            | The ID for the Active Directory tenant that the user belongs to. |
|                     | `AZURE_CLIENT_ID`            | The application client ID. |
|                     | `AZURE_USERNAME`             | The username to sign in with.
|                     | `AZURE_PASSWORD`             | The password to sign in with. |

**Note: These env variables are sensitive and should be stored in a Kubernetes `Secret` resource, then referenced by [Using Secrets as Environment Variables](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables).** 

See official MS documentation for more details on how environment base authentication works for Azure: https://docs.microsoft.com/en-us/go/azure/azure-sdk-go-authorization#use-environment-based-authentication
