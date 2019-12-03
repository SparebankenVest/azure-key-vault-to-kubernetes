---
title: "Controller"
metaTitle: "controller"
metaDescription: "This is the meta description"
---

The **Azure Key Vault Controller** (Controller for short) synchronizes Secrets, Certificates and Keys from Azure Key Vault as native `Secret`'s in Kubernetes.

Periodically the Controller will poll Azure Key Vault for version changes of the secret and apply any changes to the Kubernetes native secret.