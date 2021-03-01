# Changelog for Version 1.2

## Version 1.2.2

### Env-Injector

#### Bug Fixes

* Make sure authService exists before creating http endpoints

## Version 1.2.1

### Env-Injector Init Container

#### Features

* Handle log level and format from env variables using klog

#### Bug Fixes

* Ensure Pod Name and Namespace are injected as env vars into Pod when authService is disabled
* Only create and validate credentials when authService is enabled

### Env-Injector Sidecar Container

#### Bug Fixes

## Version 1.2.0

The most notable changes in this release are:

* The Controller support sync to ConfigMap (in addition to Secret)
* The Controller support several `AzureKeyVaultSecret`-resources pointing to same Secret/ConfigMap as long as they have different output `dataKey`'s
* The Env Injector's auth service use Mutual TLS authentication (mTLS) to secure credential exchange with Pods
* Both Controller and Env Injector has optional Prometheus metrics
* All known stability issues with version 1.1 should be fixed

### Env-Injector

#### Features

* The Env Injector's auth service use Mutual TLS authentication (mTLS) to secure credential exchange with Pods
* #38 - Optionally expose Prometheus metrics

#### Bug Fixes

* #55 - when using aad-pod-identity, env-injector fail to pull image from ACR
* #147 - akv2k8s-ca ConfigMap disappears after some hours never to come back
* #151 - secret output transform does not work - The CRD and API were using different key
* #153 - config map deleted by Kubernetes garbage collector

#### Other
* The CA Bundle sync is removed, as this is now handled during Pod mutation in the Env-Injector

### Controller

#### Features
* #18 - Sync to ConfigMap (requires AzureKeyVaultSecret `apiVersion: spv.no/v2beta1`)
* #36 - Multiple `AzureKeyVaultSecret`-resources can reference the same Secret/ConfigMap as long as they have different output `dataKey`'s
* #38 - Optionally expose Prometheus metrics

### Docs

* Docs for version `1.2` is default - added version `1.1` to version dropdown
* New features documented
* Examples/tutorials updated with latest CRD API version `apiVersion: spv.no/v2beta1`
* Installation section updated with latests changes
* Section added for Monitoring (logs and metrics)

### Helm Charts

* Standardized all labels, simplified and standardized values - breaking change requires major version bump to 2.0.0
* Support `global` values which will effect both the Controller and Env Injector, preventing value duplication
* Enable Prometheus metrics configuration and `ServiceMonitor` configuration
* Support adding extra volumes
* Use ephemeral ports internally by default to avoid running with elevated privileges   

### Chart and Image versions

| Type    |           Component                                   |                Version         |         
| ------- | ---------------------------------- | -----------------------------|
| Helm Chart | [akv2k8s](https://github.com/SparebankenVest/public-helm-charts/tree/master/stable/akv2k8s) | 2.0.0 |
| Docker Image | spvest/azure-keyvault-controller | 1.2.0 |
| Docker Image | spvest/azure-keyvault-webhook | 1.2.0 |
| Docker Image | spvest/azure-keyvault-env  | 1.2.0 |
