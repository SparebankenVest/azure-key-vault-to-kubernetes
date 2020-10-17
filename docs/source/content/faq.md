---
title: "FAQ"
description: "Most frequently asked questions"
---

## How does Akv2k8s compare to Azure Key Vault Provider for Secrets Store CSI Driver?

On a high level Akv2k8s was created to securely pass secrets through environment variables into Docker containers and applications. Azure Key Vault Provider for Secrets Store CSI Driver on the other hand was created to access secrets through volumes. It boils down how to how you want your application to access secrets. The Akv2k8s project is highly motivated by the 12 Factor App principles and believes passing configuration (including secrets) through environment variables is the way to go. If you prefer accessing secrets from a volume, use Azure Key Vault Provider for Secrets Store CSI Driver.

## Can we see the secret value when using env-injection option?

The secrets will not be revealed by env-injector and cannot be found in logs, volumes or in Kubernetes. The only place where the secrets exists is in the application process running inside the container. Depending on your security settings for your Pod and Container, you can exec into a shell in your pod and run: 

```
cat /proc/1/environ | xargs -0 -L1 |sort
```

...replacing `[pid]` with your process ID - often this is 1 in a container. This will list all env variables for the process.

To prevent this, see next question.

## Can I prevent env-injected secrets from being listed in `/proc/[pid]/environ` inside the container?

Yes. Follow Docker Container best-practices and don't run your container as root: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user

## Is Akv2k8s compatible with Google distroless images?

Yes. 

## Can I use a `AzureKeyVaultSecret` resource from a different namespace?

No. `AzureKeyVaultSecret` behaves as Kubernetes `Secret` does. You cannot reference secrets across namespaces. 

> Secret resources reside in a namespace. Secrets can only be referenced by Pods in that same namespace.

https://kubernetes.io/docs/concepts/configuration/secret/#restrictions

## What are the different Azure Key Vault authentication options available?

For the Controller:

1. Using built-in AKS cluster credentials from azure cloud config (default)
2. Using custom credentials through environment variables
3. Using aad-pod-identity

For the Env-Injector:

Same 3 options as for the Controller, plus:

1. Disable the env-injector auth service and use aad-pod-identity with your pod
2. Disable the env-injector auth service and pass credentials directly to your pod through environment variables
