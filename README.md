# azure-keyvault-controller

A Kubernetes controller that will sync secrets from Azure Key Vault to Secrets in Kubernetes.

## Prerequisites

Currently this controller depends on the [`azure-pod-identity`](https://github.com/Azure/aad-pod-identity) for authentication using Managed Service Identity (MSI). There are plans to add support for using Service Principal as an alternative to `azure-pod-identity` in the future.

## Install

#### 1. Deploy the Custom Resource Definition for AzureKeyVaultSecret

The CRD can be found here: [artifacts/crd.yaml](artifacts/crd.yaml)

#### 2. Deploy controller

An example deployment definition can be found here: [artifacts/example-controller-deployment.yaml](artifacts/example-controller-deployment.yaml)

Optional environment variables:

| Env var                       | Description |
| ----------------------------- | ----------- |
| AZURE_VAULT_FAST_RATE         | How often we check Vault for changes in secrets |
| AZURE_VAULT_SLOW_RATE         | How often we check Vault for changes in secrets, given AZURE_VAULT_MAX_FAST_ATTEMPTS has previously failed |
| AZURE_VAULT_MAX_FAST_ATTEMPTS | How many fast attempts can fail before we start using slow rate |
