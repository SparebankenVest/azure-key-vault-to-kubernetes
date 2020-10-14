---
title: "FAQ"
description: "Most frequently asked questions"
---

### How does Akv2k8s compare to Azure Key Vault Provider for Secrets Store CSI Driver?

On a high level Akv2k8s was created to securely pass secrets through environment variables into Docker containers and applications. Azure Key Vault Provider for Secrets Store CSI Driver on the other hand was created to access secrets through volumes. It boils down how to how you want your application to access secrets. The Akv2k8s project is highly motivated by the 12 Factor App principles and believes passing configuration (including secrets) through environment variables is the way to go. If you prefer accessing secrets from a volume, use Azure Key Vault Provider for Secrets Store CSI Driver.