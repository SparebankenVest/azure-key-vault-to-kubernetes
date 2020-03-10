---
title: "Inject Certificate"
description: "Inject an Azure Key Vault certificate key pair directly into a container application"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

We start by creating a definition for the Azure Key Vault secret pointing to the certificate we want to sync:

```yaml{4,8,10,11}:title=akvs-certificate-inject.yaml
apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: certificate-inject 
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-certificate # name of the akv object
      type: certificate # akv object type
```

Apply to Kubernetes:

```bash
$ kubectl apply -f akvs-certificate-inject.yaml
azurekeyvaultsecret.spv.no/certificate-inject created
```

To list AzureKeyVaultSecret's and see sync status:

```bash
$ kubectl -n akv-test get akvs
NAME                VAULT          VAULT OBJECT    SECRET NAME         SYNCHED
certificate-inject  akv2k8s-test   my-certificate  
```

Then we deploy a Pod having a env-variable pointing to the secret above.

```yaml{4,18-20,22-23}:title=certificate-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: akvs-certificate-app
  namespace: akv-test
  labels:
    app: akvs-certificate-app
spec:
  selector:
    matchLabels:
      app: akvs-certificate-app
  template:
    metadata:
      labels:
        app: akvs-certificate-app
    spec:
      containers:
      - name: akv2k8s-env-test
        image: spvest/akv2k8s-env-test:2.0.1
        args: ["PUBLIC_KEY", "PRIVATE_KEY"]
        env:
        - name: PUBLIC_KEY
          value: certificate-inject@azurekeyvault?tls.crt
        - name: PRIVATE_KEY
          value: certificate-inject@azurekeyvault?tls.key
```

Apply to Kubernetes:

```bash
$ kubectl apply -f certificate-deployment.yaml
deployment.apps/akvs-certificate-app created
```

Things to note from the Deployment yaml above:

```yaml
containers:
- name: akv2k8s-env-test
  image: spvest/akv2k8s-env-test # 1.
  args: ["PUBLIC_KEY", "PRIVATE_KEY"] # 2.
  env:
  - name: PUBLIC_KEY # 3.
    value: certificate-inject@azurekeyvault?tls.crt # 4.
  - name: PRIVATE_KEY # 5.
    value: certificate-inject@azurekeyvault?tls.key # 6.
```

1. We use a custom built Docker image for testing purposes that only outputs the content of the env-variables passed in as args in #2. Feel free to replace this with your own Docker image.
2. Again, specific for the Docker test image we are using (in #1), we pass in which environment variables we want the container to print values for 
3. Name of the environment variable containing the certificate public key
4. By using the special akv2k8s Env Injector convention `<azure-key-vault-secret-name>@azurekeyvault` to reference the AzureKeyVaultSecret `certificate-inject` we created earlier. The env-injector will download this secret from Azure Key Vault and inject into the executable running in your Container.
5. Name of the environment variable containing the certificate private key
6. Same as 4. - only for the certificate private key

To see the log output from your Pod, execute the following command:

```
kubectl -n akv-test logs deployment/akvs-certificate-app
```

### Cleanup

```bash
kubectl delete -f akvs-secret-inject.yaml
kubectl delete -f secret-deployment.yaml
```