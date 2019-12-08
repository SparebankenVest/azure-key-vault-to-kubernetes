---
title: "Authentication"
metaTitle: "Authentication"
metaDescription: "Learn about the different options for authenticating with Azure Key Vault."
index: 30
---

By default both the Controller and the Env Injector will use the credentials found in Cloud Config on the host to authenticate with Azure Key Vault. This is the same credentials as the Kubernetes cluster use when interacting with Azure to create VM's, Load Balancers and other cloud infrastructure.

<div class="alert alert-warning" role="alert">
  Note: if you do not run Kubernetes on Azure <a href="#override-default-authentication">override default authentication</a>
</div>

Cloud Config for Azure is located at `/etc/kubernetes/azure.json`. The Controller will map this as a read only volume and read the credentials. For the Env Injector it's a bit different. Since the Env Injector is not in full control over how the original container is setup, it will copy the azure.json to a local shared volume, chmod `azure.json` to 444 in case the original container is running under a less privileged user (which is a good practice) and not get access to the credentials.

Currently only one situations has been identified, where the above does not work:

* When a [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) is configured in the cluster, preventing containers from reading from the host, two solutions exists:  
  1. Change the Pod Security Policy to list `/etc/kubernetes/azure.json` under [AllowedHostPaths](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) 
  2. Or [override default authentication](#override-default-authentication). 

**For default authentication move to the next section about [Authorization](#authorization). To override default authentication, read on.**

## Override default authentication

It is possible to give the Controller and/or the Env Injector specific credentials to authenticate with Azure Key Vault.

The authentication requirements for the Controller and Env Injector are covered below.

### Custom Authentication for the Controller 

The Controller will need Azure Key Vault credentials to get Secrets from Azure Key Vault and store them as Kubernetes Secrets. See [Authentication options](#authentication-options) below.

### Custom Authentication for Env Injector

To use custom authentication for the Env Injector, set  the environment variable `CUSTOM_AUTH` to `true`.

By default each Pod using the Env Injector pattern must provide their own credentials for Azure Key Vault using [Authentication options](#authentication-options) below.

To avoid that, support for a more convenient solution is added where the Azure Key Vault credentials in the Env Injector (using [Authentication options](#authentication-options) below) is "forwarded" to the the Pods. This is enabled by setting the environment variable `CUSTOM_AUTH_INJECT` to `true`. Env Injector will then create a Kubernetes Secret containing the credentials and modify the Pod's env section to reference the credentials in the Secret. 

### Custom Authentication Options

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
