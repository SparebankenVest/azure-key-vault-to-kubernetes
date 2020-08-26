---
title: "Prerequisites"
description: "A quick overview of the prerequisites needed to complete the tutorials"
---

Below are a set of Azure Key Vault and Kubernetes resources that must be in place to walk through the tutorials.

> Note: The resource names used below are optional (like AKV `akv2k8s-test`), but sticking with the suggested names will make it easier and more consistent as you walk through the tutorials

## Azure Resources

Azure Resource Group:

```bash
az group create -l westeurope -n akv2k8s-test
```

Azure Key Vault:

```bash
az keyvault create -n akv2k8s-test -g akv2k8s-test
```

### Add secret - required for secret-tutorials

Add Secret to Azure Key Vault:

```bash
az keyvault secret set --vault-name akv2k8s-test --name my-secret --value "My super secret"
```

Authorize Access to Secrets:

```bash
az keyvault set-policy --n akv2k8s-test --spn <spn for akv2k8s> --secret-permissions get 
```

### Add certificate - required for certificate-tutorials

```bash
az keyvault certificate create --vault-name akv2k8s-test --name my-certificate -p "$(az keyvault certificate get-default-policy -o json)"
```

Authorize Access to Certificates:

```bash
az keyvault set-policy --n akv2k8s-test --spn <spn for akv2k8s> --certificate-permissions get 
```

### Add signing key - required for signing-key-tutorials

```bash
az keyvault key create --vault-name akv2k8s-test --name my-key
```

Authorize Access to Keys:

```bash
az keyvault set-policy --n akv2k8s-test --spn <spn for akv2k8s> --key-permissions get 
```

## Kubernetes Resources

Create namespace:

```yaml:title=namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: akv-test
  labels:
    azure-key-vault-env-injection: enabled
```

Apply configuration:

```bash
kubectl apply -f namespace.yaml
```

### That's it! You should now be ready to do all or any of the tutorials of akv2k8s!
