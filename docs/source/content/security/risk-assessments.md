---
title: "Risk Assessments"
description: "Learn about the risk assessments the akv2k8s project has done"
---

To help assess if the akv2k8s project is within the ... here is a list of some of the perticulars and the risk assessments we did around those topics.

When developing the akv2k8s project there are many

## How to handle credentials

Credentials to Azure Key Vault is needed by both the controller that syncs AKV secrets into Kubernetes secrets, and the env-injector that inject AKV secrets into container applications.


### The Controller

The controller is the easiest to evaluate, as it's not directly exposed together with the applications using them. It's a centrally installed component that can be secured using RBAC mechanisms in Kubernetes and prevent everyone except admins access to any secrets, in perticular the AKV credentials the controller needs. The risk of exposing credentials to uninvited guests is low, and no higher than any other components in Kubernetes handling sensitive data. In practice, the same security precautions must be taken as with Kubernetes Secrets in general. The Kubernetes project have documented this here:

### The Env-Injector

Compared to the Controller the injector is quite different, as it's directly exposed together with the Pod and Containers requesting secret injection. In practice this means the code that downloads the secrets for Azure Key Vault runs inside the application Container and are executed before the original executable of that container. After the container has started, a Kubernetes user with the right credentials are able to exec into the container. Several steps have been taken to avoid exposing sensitive data in this scenario and are explained below. Another scenario is data stored in Kubernetes Secrets
