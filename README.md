# Azure Key Vault To Kubernetes

[![Release](https://img.shields.io/github/release/atrox/sync-dotenv.svg?style=flat-square)](https://github.com/SparebankenVest/azure-key-vault-to-kubernetes/releases/latest)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FSparebankenVest%2Fazure-key-vault-to-kubernetes%2Fbadge%3Fref%3Dmaster&style=flat-square&label=github%20actions)](https://actions-badge.atrox.dev/SparebankenVest/azure-key-vault-to-kubernetes/goto?ref=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/SparebankenVest/azure-key-vault-to-kubernetes?style=flat-square)](https://goreportcard.com/report/github.com/SparebankenVest/azure-key-vault-to-kubernetes)
![Docker Pulls](https://img.shields.io/docker/pulls/spvest/azure-keyvault-controller?label=controller%20downloads&style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/spvest/azure-keyvault-webhook?label=env-injector%20downloads&style=flat-square)

Project status: Stable - multipal financial institutions are running this project on production Kubernetes clusters

Read the announcement: https://mrdevops.io/introducing-azure-key-vault-to-kubernetes-931f82364354

**Full documentation is available at https://akv2k8s.io**

## Overview

Azure Key Vault to Kubernetes (akv2k8s) has two components for handling Azure Key Vault Secrets in Kubernetes:

* Azure Key Vault Controller
* Azure Key Vault Env Injector

The **Azure Key Vault Controller** (Controller for short) is for synchronizing Secrets, Certificates and Keys from Azure Key Vault to native `Secret`'s in Kubernetes.

The **Azure Key Vault Env Injector** (Env Injector for short) is a Kubernetes Mutating Webhook transparently injecting Azure Key Vault secrets as environment variables into programs running in containers, without touching disk or in any other way expose the actual secret content outside the program.

## Goals

Goals for this project was:

1. Avoid a direct program dependency on Azure Key Vault for getting secrets, and adhere to the 12 Factor App principle for configuration (https://12factor.net/config)
2. Make it simple, secure and low risk to transfer Azure Key Vault secrets into Kubernetes as native Kubernetes secrets
3. Securely and transparently be able to inject Azure Key Vault secrets as environment variables to applications, without having to use native Kubernetes secrets

All of these goals are met.

## Requirements

* Kubernetes version >= 1.9 
* Enabled admission controllers: MutatingAdmissionWebhook and ValidatingAdmissionWebhook
* RBAC enabled
* Default [authentication](#authentication) requires Kubernetes cluster running in Azure - use custom authentication if running outside Azure

## Installation

It's recommended to use Helm charts for installation:

Controller: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-controller

Env Injector: https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/azure-key-vault-env-injector

For more details, see full documentation at https://akv2k8s.io.


### Installation without Helm

If Helm is not an option in Kubernetes, use Helm on a local computer to generate the Kubernetes templates like below:

`helm install --debug --dry-run <options>`

See the individual Helm charts above for `<options>`.

## Credits

Credit goes to Banzai Cloud for coming up with the [original idea](https://banzaicloud.com/blog/inject-secrets-into-pods-vault/) of environment injection for their [bank-vaults](https://github.com/banzaicloud/bank-vaults) solution, which they use to inject Hashicorp Vault secrets into Pods.

## Contributing

Development of Azure Key Vault for Kubernetes happens in the open on GitHub, and encourage users to:

* Send a pull request with any security issues found and fixed
* Send a pull request with your new features and bug fixes
* Report issues on security or other issues you have come across
* Help new users with issues they may encounter
* Support the development of this project and star this repo!

**[Code of Conduct](CODE_OF_CONDUCT.md)**

Sparebanken Vest has adopted a Code of Conduct that we expect project participants to adhere to. Please read the full text so that you can understand what actions will and will not be tolerated.

**[License](LICENSE)**

Azure Key Vault to Kubernetes is licensed under Apache License 2.0.
