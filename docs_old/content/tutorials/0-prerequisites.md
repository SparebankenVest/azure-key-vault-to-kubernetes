---
title: "Prerequisites"
metaTitle: "Prerequisites"
metaDescription: "A set of commands to create all prerequisite resources needed to complete tutorials"
index: 51
---

Below are a set of common prerequisites for all the tutorials.

## Azure Resources

Below are a set of Azure CLI commands to create necessary Azure resources.

Azure Resource Group:

```none
az group create -l westeurope -n akv2k8s-test
```

Azure Key Vault:

```none
az keyvault create -n akv2k8s-test -g akv2k8s-test
```

### Add secret - required for secret-tutorials

Add Secret to Azure Key Vault:

```none
az keyvault secret set --vault-name akv2k8s-test --name my-secret --value "My super secret"
```

Authorize Access to Secrets:

```none
az keyvault set-policy --n akv2k8s-test --spn <spn for akv2k8s> --secret-permissions get 
```

### Add certificate - required for certificate-tutorials

```none
az keyvault certificate create --vault-name akv2k8s-test --name my-certificate -p "$(az keyvault certificate get-default-policy)"
````

Authorize Access to Certificates:

```none
az keyvault set-policy --n akv2k8s-test --spn <spn for akv2k8s> --certificate-permissions get 
```

## Kubernetes Resources

Create namespace:

```yaml
# namespace.yaml

apiVersion: v1
kind: Namespace
metadata:
  name: akv-test
  labels:
    azure-key-vault-env-injection: enabled
```

Apply configuration:

```none
kubectl apply -f namespace.yaml
```

The Env Injector is developed using a Mutating Admission Webhook that triggers just before every Pod gets created. To allow cluster administrators some control over which Pods this Webhook gets triggered for, it must be enabled per namespace using the `azure-key-vault-env-injection` label.
