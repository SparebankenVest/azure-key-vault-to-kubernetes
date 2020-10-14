---
title: "Inject PFX Certificate"
description: "Inject a PFX certificate from Azure Key Vault as environment variables into an application"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

The certificate handling in certain programming languages like Microsoft .NET has a
preference for certificates in the binary PKCS12 format, commonly known as PFX. To extract the raw
PKCS12 certificate from Azure Key Vault, you need to **get the Secret object of the Certificate**!

This tutorial is EXACTLY like the [Inject Certificate](2-certificate) tutorial, except the highlighted
last line below:

```yaml{11}:title=akvs-certificate-inject.yaml
apiVersion: spv.no/v1
kind: AzureKeyVaultSecret
metadata:
  name: certificate-inject
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-certificate # name of the akv object
      type: secret # akv object type
```

By specifying `type: secret` instead of `certificate`, Azure Key Vault will respond with the PKCS12 certificate
that can be injected directly into your application.

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

```yaml:title=certificate-deployment.yaml
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

```yaml{3,4,6-9}
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