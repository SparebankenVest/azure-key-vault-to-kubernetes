---
title: "Inject Secret"
description: "Inject an Azure Key Vault secret directly into a container application"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

We start by creating a definition for the Azure Key Vault secret we want to inject:

```yaml:title=akvs-secret-inject.yaml
apiVersion: spv.no/v1
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
$ kubectl apply -f akvs-secret-inject.yaml
azurekeyvaultsecret.spv.no/secret-inject created
```

List AzureKeyVaultSecret's:

```bash
$ kubectl -n akv-test get akvs
NAME           VAULT          VAULT OBJECT   SECRET NAME         SYNCHED
secret-inject  akv2k8s-test   my-secret
```

Then we deploy a Pod having a env-variable pointing to the secret above.

```yaml:title=secret-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: akvs-secret-app
  namespace: akv-test
  labels:
    app: akvs-secret-app
spec:
  selector:
    matchLabels:
      app: akvs-secret-app
  template:
    metadata:
      labels:
        app: akvs-secret-app
    spec:
      containers:
      - name: akv2k8s-env-test
        image: spvest/akv2k8s-env-test:2.0.1
        args: ["TEST_SECRET"]
        env:
        - name: TEST_SECRET
          value: "secret-inject@azurekeyvault" # ref to akvs
```

Apply to Kubernetes:

```bash
$ kubectl apply -f secret-deployment.yaml
deployment.apps/akvs-secret-app created
```

Things to note from the Deployment yaml above:

```yaml{3,4,6,7}
containers:
  - name: akv2k8s-env-test
    image: spvest/akv2k8s-env-test:2.0.1 # 1.
    args: ["TEST_SECRET"] # 2.
    env:
    - name: TEST_SECRET # 3.
      value: "secret-inject@azurekeyvault" # 4.
```

1. We use a custom built Docker image for testing purposes that only outputs the content of the env-variables passed in as args in #2. Feel free to replace this with your own Docker image.
2. Again, specific for the Docker test image we are using (in #1), we pass in which environment variables we want the container to print values for 
3. Name of the environment variable
4. By using the special akv2k8s Env Injector convention `<azure-key-vault-secret-name>@azurekeyvault` to reference the AzureKeyVaultSecret `secret-inject` we created earlier. The env-injector will download this secret from Azure Key Vault and inject into the executable running in your Container.

To see the log output from your Pod, execute the following command:

```
kubectl -n akv-test logs deployment/akvs-secret-app
```

### Cleanup

```bash
kubectl delete -f akvs-secret-inject.yaml
kubectl delete -f secret-deployment.yaml
```