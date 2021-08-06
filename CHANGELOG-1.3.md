---
title: "Changelog for Version 1.3"
description: "All changes in version 1.3"
---

# Changelog for Version 1.3

## Version 1.3.0

The most notable changes in this release are:

* Ability to run controller in specific namespace only
* Ability to allow akvs objects with different labels to be handled by controllers with different authorization policies
* Generate CRD's from code with controller-gen


### Controller

#### Features

* #82 - Allow controller to run in specific namespace only
* #159 - Generate crd with controller gen
* #174 - Export certificates stored as Base64 PFX in Azure Key Vault secret object as Kubernetes TLS secret
* #178 - Allow akvs objects with different labels to be handled by controllers with different authorization policies
* #202 - Upgrade dependencies k8s to v0.21.2
* Upgrade to Go 1.16.5
* Upgrade alpine base image to 3.14.0

#### Bug Fixes

* #209 - Fix using an EC header/footer for ECDSA keys


### Docs

* Docs for version `1.3` is default - added version `1.2` to version dropdown

### Helm Charts

* Add generated crd from SparebankenVest/azure-key-vault-to-kubernetes#159
* Ignore files in .helmignore
* Add support for watchAllNamespaces
* SparebankenVest/public-helm-charts#45 - Upgrade cert-manager CRD's to api version v1
* Remove unused RUNNING_INSIDE_AZURE_AKS env
* SparebankenVest/public-helm-charts#57 - Add optional pod annotations to the controller
* SparebankenVest/public-helm-charts#59 - Add optional pod security context

### Chart and Image versions

| Type         | Component                                                                                          | Version |
| ------------ | -------------------------------------------------------------------------------------------------- | ------- |
| Helm Chart   | [akv2k8s](https://github.com/SparebankenVest/public-helm-charts/tree/akv2k8s-2.1.0/stable/akv2k8s) | 2.1.0   |
| Docker Image | spvest/azure-keyvault-controller                                                                   | 1.3.0   |
| Docker Image | spvest/azure-keyvault-webhook                                                                      | 1.3.0   |
| Docker Image | spvest/azure-keyvault-env                                                                          | 1.3.0   |
