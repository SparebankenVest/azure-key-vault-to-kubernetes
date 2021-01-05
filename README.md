<p align="center"><img src="akv2k8s.png" width="300" /></p>
<h1 align="center">Azure Key Vault to Kubernetes</h1>
<p align="center">

  <a href="https://github.com/SparebankenVest/azure-key-vault-to-kubernetes/actions">
    <img src="https://img.shields.io/github/workflow/status/sparebankenvest/azure-key-vault-to-kubernetes/build?style=flat&label=build" alt="Build Status">
  </a>

  <a href="https://goreportcard.com/report/github.com/SparebankenVest/azure-key-vault-to-kubernetes">
    <img src="https://goreportcard.com/badge/github.com/SparebankenVest/azure-key-vault-to-kubernetes?style=flat" alt="Go Report Card">
  </a>
 
  <a href="https://github.com/SparebankenVest/azure-key-vault-to-kubernetes/releases/latest">
    <img src="https://img.shields.io/github/v/release/sparebankenvest/azure-key-vault-to-kubernetes?sort=semver&style=flat&label=latest%20release" alt="Release">
  </a>

  <a href="https://github.com/SparebankenVest/azure-key-vault-to-kubernetes/releases/latest">
    <img src="https://img.shields.io/github/v/tag/sparebankenvest/azure-key-vault-to-kubernetes?style=flat&label=latest%20tag" alt="Tag">
  </a>

  <a href="https://hub.docker.com/r/spvest/azure-keyvault-controller">
    <img src="https://img.shields.io/docker/pulls/spvest/azure-keyvault-controller?label=controller%20downloads&style=flat" alt="Docker Pulls">
  </a>

  <a href="https://hub.docker.com/r/spvest/azure-keyvault-webhook">
    <img src="https://img.shields.io/docker/pulls/spvest/azure-keyvault-webhook?label=env-injector%20downloads&style=flat" alt="Docker Pulls">
  </a>

<p>
  
<p align="center"><i>Azure Key Vault to Kubernetes (akv2k8s) makes Azure Key Vault secrets, certificates and keys available to your applications in Kubernetes, in a simple and secure way.</i></p> 

<p align="center"><i>Documentation available at <a href="https://akv2k8s.io">https://akv2k8s.io</a>. Join our <a href="https://join.slack.com/t/akv2k8s/shared_invite/zt-gsptc7if-g_lW4jHrYVrLGMX0MdYw_g">Slack Workspace</a> to ask questions to the akv2k8s community.</i></p>

<p align="center"><i>Please spare one minute to take our survey: <a href="https://www.surveymonkey.com/r/HMFZVYR">https://www.surveymonkey.com/r/HMFZVYR</a>. Why? We have no ide how many are using Akv2k8s, except through user interaction here on GitHub. More importantly - what can we do to make Akv2k8s even better?</i></p>

## Overview

Azure Key Vault to Kubernetes (akv2k8s) will make Azure Key Vault objects available to Kubernetes in two ways:

* As native Kubernetes `Secret`s 
* As environment variables directly injected into your Container application

The **Azure Key Vault Controller** (Controller for short) is responsible for synchronizing Secrets, Certificates and Keys from Azure Key Vault to native `Secret`'s in Kubernetes.

The **Azure Key Vault Env Injector** (Env Injector for short) is responsible for transparently injecting Azure Key Vault secrets as environment variables into Container applications, without touching disk or expose the actual secret to Kubernetes.

## Goals

Goals for this project was:

1. Avoid a direct program dependency on Azure Key Vault for getting secrets, and adhere to the 12 Factor App principle for configuration (https://12factor.net/config)
2. Make it simple, secure and low risk to transfer Azure Key Vault secrets into Kubernetes as native Kubernetes secrets
3. Securely and transparently be able to inject Azure Key Vault secrets as environment variables to applications, without having to use native Kubernetes secrets

All of these goals are met.

## Installation

For installation instructions, see documentation at https://akv2k8s.io/installation/

## Credits

Credit goes to Banzai Cloud for coming up with the [original idea](https://banzaicloud.com/blog/inject-secrets-into-pods-vault/) of environment injection for their [bank-vaults](https://github.com/banzaicloud/bank-vaults) solution, which they use to inject Hashicorp Vault secrets into Pods.

## Contributing

Development of Azure Key Vault for Kubernetes happens in the open on GitHub, and encourage users to:

* Send a pull request with 
  * any security issues found and fixed
  * your new features and bug fixes
  * updates and improvements to the documentation
* Report issues on security or other issues you have come across
* Help new users with issues they may encounter
* Support the development of this project and star this repo!

**[Code of Conduct](CODE_OF_CONDUCT.md)**

Sparebanken Vest has adopted a Code of Conduct that we expect project participants to adhere to. Please read the full text so that you can understand what actions will and will not be tolerated.

**[License](LICENSE)**

Azure Key Vault to Kubernetes is licensed under Apache License 2.0.

### Contribute to the Documentation

The documentation is located in a seperate repository at https://github.com/SparebankenVest/akv2k8s-website. We're using Gatsby + MDX (Markdown + JSX) to generate static docs for https://akv2k8s.io.

