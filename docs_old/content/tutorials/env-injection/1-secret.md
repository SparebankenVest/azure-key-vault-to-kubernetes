---
title: "Inject Secret"
metaTitle: "Inject Secret"
metaDescription: "Tutorial covering how to inject a secret from Azure Key Vault directly into a container as environment variable."
index: 54
---

**Note: The [prerequisites](/tutorials/0-prerequisites) are required to complete this tutorial.**

This tutorial will cover how to inject a secret from Azure Key Vault directly into a container as environment variable.

We start by creating a definition for the Azure Key Vault secret we want to inject:

```yaml
# secret-inject.yaml

apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: secret-inject 
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-secret # name of the akv object
      type: secret # akv object type
```

Apply to Kubernetes:

```bash
$ kubectl apply -f secret-sync.yaml
azurekeyvaultsecret.spv.no/secret-sync created
```

List AzureKeyVaultSecret's:

```bash
$ kubectl -n akv-test get akvs

NAME          VAULT          VAULT OBJECT   SECRET NAME         SYNCHED
secret-sync   akv2k8s-test   my-secret
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
        - name: TEST_SECRET
          value: "secret-inject@azurekeyvault"
        - name: ENV_INJECTOR_LOG_LEVEL
          value: debug
```

Apply to Kubernetes:

```bash
$ kubectl apply -f deployment.yaml
azurekeyvaultsecret.spv.no/secret-inject created
```

Things to note from the Deployment yaml above:

```yaml
containers:
  - name: akv2k8s-env-test
    image: spvest/akv2k8s-env-test # 1.
    env:
    - name: TEST_SECRET # 2.
      value: "secret-inject@azurekeyvault" # 3.
    - name: ENV_INJECTOR_LOG_LEVEL # 3.
      value: debug
```

1. We use a custom built Docker image that only outputs the content of the env-variable `TEST_SECRET` to the console. Feel free to replace this with your own Docker image.

2. The env-variable this Docker image expects and will output. When using your own Docker image, set the env-variables your image expects using convention in 3.

3. We use the akv2k8s injector convention to reference the AzureKeyVaultSecret `secret-inject` we created earlier ([akvs-name]@azurekeyvault). The env-injector will download this secret from Azure Key Vault and inject into the executable running in your Container.

4. A optional env-variable you can pass to your container to set the log-level of the env-injector and optionally get detailed log output during startup of your pod.

To see the log output from your Pod, execute the following command:

`kubectl -n akv-test logs deployment/akv2k8s-test-injection`

### Cleanup

```bash
kubectl -n akv-test delete AzureKeyVaultSecret secret-inject
kubectl -n akv-test delete deployment akv2k8s-test-injection
```