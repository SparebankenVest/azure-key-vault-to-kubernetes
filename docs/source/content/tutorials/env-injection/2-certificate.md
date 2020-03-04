---
title: "Inject Certificate"
description: "Inject a certificate key pair from Azure Key Vault as environment variables into an application"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

This tutorial will cover how to inject a certificate key pair from Azure Key Vault directly into a container as a set of environment variables.

We start by creating a definition for the Azure Key Vault secret pointing to the certificate
we want to sync (certificate created in [prerequisites](../prerequisites)):

```yaml
# certificate-inject.yaml

apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: certificate-inject 
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-certificate
      type: certificate
```

Apply to Kubernetes:

```bash
$ kubectl apply -f certificate-inject.yaml
azurekeyvaultsecret.spv.no/certificate-inject created
```

To list AzureKeyVaultSecret's and see sync status:

```bash
$ kubectl -n akv-test get akvs
NAME                VAULT          VAULT OBJECT    SECRET NAME         SYNCHED
certificate-inject  akv2k8s-test   my-certificate  
```



Then we deploy a Pod having a env-variable pointing to the secret above.

```yaml
# deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: akv2k8s-test-injection
  namespace: akv-test
  labels:
    app: akv2k8s-test-injection
spec:
  selector:
    matchLabels:
      app: akv2k8s-test-injection
  template:
    metadata:
      labels:
        app: akv2k8s-test-injection
    spec:
      containers:
      - name: akv2k8s-env-test
        image: spvest/akv2k8s-env-test
        env:
        - name: PUBLIC_KEY
          value: certificate-inject@azurekeyvault?tls.crt
        - name: PRIVATE_KEY
          value: certificate-inject@azurekeyvault?tls.key
        - name: ENV_INJECTOR_LOG_LEVEL
          value: debug
```

inject secret by referencing the **AzureKeyVaultSecret** above using a replacement marker (`azurekeyvault@<AzureKeyVaultSecret>`) and query (`?`) to point to private/public key:

```yaml
env:
  - name: PUBLIC_KEY
    value: certificate-inject@azurekeyvault?tls.crt
  - name: PRIVATE_KEY
    value: certificate-inject@azurekeyvault?tls.key
```
