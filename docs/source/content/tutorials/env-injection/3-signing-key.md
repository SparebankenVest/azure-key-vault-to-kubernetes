---
title: "Inject Signing Key"
description: "Inject a signing key from Azure Key Vault as environment variable into an application"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

We start by creating a definition for the Azure Key Vault signing key we want to inject:

```yaml:title=akvs-signing-key-inject.yaml
apiVersion: spv.no/v1
kind: AzureKeyVaultSecret
metadata:
  name: signing-key-inject 
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-key # name of the akv object
      type: key # akv object type
```

Apply to Kubernetes:

```bash
$ kubectl apply -f akvs-signing-key-inject.yaml
azurekeyvaultsecret.spv.no/signing-key-inject created
```

List AzureKeyVaultSecret's:

```bash
$ kubectl -n akv-test get akvs
NAME                VAULT          VAULT OBJECT   SECRET NAME         SYNCHED
signing-key-inject  akv2k8s-test   my-key
```

Then we deploy a Pod having a env-variable pointing to the secret above.

```yaml:title=signing-key-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: akvs-signing-key-app
  namespace: akv-test
  labels:
    app: akvs-signing-key-app
spec:
  selector:
    matchLabels:
      app: akvs-signing-key-app
  template:
    metadata:
      labels:
        app: akvs-signing-key-app
    spec:
      containers:
      - name: akv2k8s-env-test
        image: spvest/akv2k8s-env-test:2.0.1
        args: ["TEST_SIGNING_KEY"]
        env:
        - name: TEST_SIGNING_KEY
          value: "signing-key-inject@azurekeyvault" # ref to akvs
```

Apply to Kubernetes:

```bash
$ kubectl apply -f signing-key-deployment.yaml
deployment.apps/akvs-signing-key-app created
```

Things to note from the Deployment yaml above:

```yaml{3,4,6,7}
containers:
  - name: akv2k8s-env-test
    image: spvest/akv2k8s-env-test:2.0.1 # 1.
    args: ["TEST_SIGNING_KEY"] # 2.
    env:
    - name: TEST_SIGNING_KEY # 3.
      value: "secret-inject@azurekeyvault" # 4.
```

1. We use a custom built Docker image for testing purposes that only outputs the content of the env-variables passed in as args in #2. Feel free to replace this with your own Docker image.
2. Again, specific for the Docker test image we are using (in #1), we pass in which environment variables we want the container to print values for 
3. Name of the environment variable
4. By using the special akv2k8s Env Injector convention `<azure-key-vault-secret-name>@azurekeyvault` to reference the AzureKeyVaultSecret `signing-key-inject` we created earlier. The env-injector will download this signing key from Azure Key Vault and inject into the executable running in your Container.

To see the log output from your Pod, execute the following command:

```
kubectl -n akv-test logs deployment/akvs-signing-key-app
```

### Cleanup

```bash
kubectl delete -f akvs-signing-key-inject.yaml
kubectl delete -f signing-key-deployment.yaml
```