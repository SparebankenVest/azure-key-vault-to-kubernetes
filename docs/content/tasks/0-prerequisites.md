---
title: "Prerequisites"
metaTitle: "Prerequisites"
metaDescription: "A list of all prerequisites needed for completing proceeding tasks"
index: 0
---

Below are a set of Azure CLI commands to create necessary Azure resources used in coming taks.

Create a Azure resource group:

```none
az group create -l westeurope -n akv2k8s-test
```

Create a Azure Key Vault:

```none
az keyvault create -n akv2k8s-test -g akv2k8s-test
```

Create a Secret in Azure Key Vault:

```none
az keyvault secret set --vault-name akv2k8s-test --name my-secret --value "My super secret"
```

Authorize Azure Key Vault to Kubernetes to access secrets:

```none
az keyvault set-policy --n  akv2k8s-test --spn <spn for akv2k8s> --secret-permissions get 
```
