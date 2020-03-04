---
title: "Inject PFX Certificate"
description: "Inject PFX certificates from Azure Key Vault as environment variables into an application"
---

> **Note: The [prerequisites](../prerequisites) are required to complete this tutorial.**

# Inject PFX Certficiate

The certificate handling in certain languages like the `dotnet` *X509Certificate2* library has a
preference for certificates in the binary PFX format. This toturial is a step by step
instruction on how to inject PFX certificates using the *Azure Key Vault Env Injector*.

Requirements:
* Env Injector must be installed in Kubernetes cluster.
* An Azure Key Vault named `akv2k8s-test`.
* Authentication and authorization configured.
* We are working in the `akv-test` namespace which requires the label `azure-key-vault-env-injection: enabled` for Env Injection.


Start by uploading your certificate to Azure Key Vault. If you don't have one
you can create a self signed certificate using the portal or Azure CLI. We use
the name `my-certificate`. For more information please see the [Azure CLI Key
Vault reference](https://docs.microsoft.com/en-us/cli/azure/keyvault/certificate?view=azure-cli-latest#az-keyvault-certificate-create).
```bash
$ az keyvault certificate create --vault-name akv2k8s-test --name my-certificate -p "$(az keyvault certificate get-default-policy)"
```

The following AzureKeyVaultSecret specification can be used as a base to retrive
your certificate. As long as the object type is set to `secret`, we will tell
Azure Key Vault to output a PFX formatted certificate with private key included.
Also notice that there is no `output` section in this AzureKeyVaultSecret as we
will use the Env Injector to inject the certificate at runtime.
```yaml
# secret-cert.yaml

apiVersion: spv.no/v1alpha1
kind: AzureKeyVaultSecret
metadata:
  name: secret-cert
  namespace: akv-test
spec:
  vault:
    name: akv2k8s-test # name of key vault
    object:
      name: my-certificate #  name of the certificate in akv
      type: secret # using type as secret exports pfx with private key
```

Apply the secret to Kubernetes:
```bash
$ kubectl apply -f secret-cert.yaml
azurekeyvaultsecret.spv.no/secret-cert created
```

We can now test that the certificate injection is working properly by creating a
pod with the following environment variables. Note that even though the Env
Injector is tested with numerous container configurations, there is a
requirement to have valid certificate chains installed on the container. This
package is called `ca-certificates` inn almost all Linux distributions.
```yaml
# pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: akv-test-app
  namespace: akv-test
  labels:
    app: akv-test-app
spec:
  containers:
  - name: akv-test-app
    image: circleci/node:lts-buster # we use an image that has `ca-certificates` installed.
    env:
    - name: MESSAGE
      value: "Hello from akv2k8s.io! Here is your certificate:"
    - name: CERTIFICATE
      value: secret-cert@azurekeyvault # we refer to the secret by the Env Injector convention <name of secret>@azurekeyvault
    command: ["printenv"]
    args: ["MESSAGE", "CERTIFICATE"]
```

Create the `akv-test-app` pod in Kubernetes:
```bash
$ kubectl apply -f pod.yaml

azurekeyvaultsecret.spv.no/secret-cert created
```

Fetch the logs from the `akv-test-app` pod:
```bash
$ kubectl -n akv-test logs akv-test-app

level=info msg="starting process /usr/bin/printenv [printenv MESSAGE CERTIFICATE]"
Hello from akv2k8s.io! Here is your certificate:
MIIKRAIBAzCCCgQGCSqGSIb3DQEHAaCCCfUEggnxMIIJ7TCCBg4GCSqGSIb3DQEHAaCCBf8EggX7MIIF9zCCBfMGCyqGSIb3DQEMCgECoIIE9jCCBPI
<base64 data snipped for readability>
81DA3MB8wBwYFKw4DAhoEFAKs60G2Xo3i5SdjjGTSEfG586O9BBSXZcH2ukRQjnIT//44DpX0y7+OKA==
```

Delete the Pod to clean up:
```bash
$ kubectl -n akv-test delete pod akv-test-app

pod "akv-test-app" deleted
```