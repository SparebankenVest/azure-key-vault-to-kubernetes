---
title: "Authentication with Azure Key Vault"
description: "Learn about the different options for authenticating with Azure Key Vault."
---

By default both the Controller and the Env Injector will assume it is running on Azure (since Azure Key Vault is most commonly used in Azure) - and use the default AKS credentials for authentication (a Service Principal or Azure Managed Identities) - unless custom authentication is provided.

The Controller and Env-Injector have to handle AKV authentication quite differently, as the Controller is centralized and the Env-Injector executes in context of Pods.

To get more options for AKV authentication, see:
  * [AKV Authentication with the Controller](#akv-authentication-with-the-controller) for AKV Controller authentication options
  * [AKV Authentication with the Env-Injector](#akv-authentication-with-the-env-injector) for AKV Env-Injector authentication options

## Situations where Default Authentication does not Work

Currently only one situations has been identified, where default authentication does not work inside Azure.

**When a [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is configured in the cluster, preventing containers from reading from the host.**

Two solutions exists:  
  1. Change the Pod Security Policy to list `/etc/kubernetes/azure.json` under [AllowedHostPaths](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) 
  2. Or use custom authentication (see below). 

## AKV Authentication with the Controller

The Controller will need Azure Key Vault credentials to get Secrets from Azure Key Vault and store them as Kubernetes Secrets. **If the default option (AKS credentials) works for you, use that.** If not, use custom authentication by passing inn the value `keyVault.customAuth.enabled=true` to the Controller and pick one of the [Authentication options](#custom-authentication-options) described below.

Fore more details, see the [Controller Helm Chart](/stable/azure-key-vault-controller/README/#installing-the-chart).

## AKV Authentication with the Env-Injector

The Env-Injector execute locally inside your Pod and needs access to Azure Key Vault credentials to inject secrets. You can either use default authentication (AKS credentials) or custom authentication. 

Below we outline some guidelines to when you should use Default or Custom authentication. 

|                                                      | Default | Custom Authentication |
| ---------------------------------------------------- | :-----------------------: | :---------------------------: |
| Kubernetes runs on Azure AKS          | &#10004;||
| Kubernetes runs outside Azure           | | &#10004;|

|                                                      | Default | Custom Authentication |
| ---------------------------------------------------- | :-----------------------: | :---------------------------: |
| Using one Azure Key Vault per cluster                | &#10004;                  |                               |
| Using multiple Azure Key Vaults per cluster (like one Key Vault per application) and it is OK to use the same credentials to all Key Vaults | &#10004;                  |                               |
| Multi-tenant environment (multiple Azure Key Vaults per cluster) |                           | &#10004;                      |

Implications:

|                                                      | Default | Custom Authentication |
| ---------------------------------------------------- | :-----------------------: | :---------------------------: |
| Provide credentials only once, during Env-Injector install | &#10004;
| Provide credentials to every Pod using Env-Injector | | &#10004;|
| The same Azure Key Vault credentials used in all Pods | &#10004; ||

### Custom AKV Authentication with the Env-Injector

Custom AKV Authentication for the Env-Injector means providing AKV credentials to every Pod using environment injection. Typically this means in every Kubernetes Deployment definition. 

Two options are currently available:

1. Use Microsft's [AAD Pod Identity](https://github.com/Azure/aad-pod-identity) (see [Using Custom Authentication with AAD Pod Identity](/stable/azure-key-vault-env-injector/README/#using-custom-authentication-with-aad-pod-identity))
2. Provide credentials for each Pod using [Authentication options](#custom-authentication-options) below.

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
