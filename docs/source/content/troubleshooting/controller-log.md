---
title: "Get the akv2k8s Controller Log"
description: "How to access the Controller log and specify log level"
---

```bash
kubectl -n akv2k8s logs deployment/azure-key-vault-controller
```

To set log-level for Controller, pass inn environment variable `LOG_LEVEL` to the container or the `logLevel` parameter for the Helm Chart. 

The Controller uses Logrus for logging, supporting seven log levels: https://github.com/Sirupsen/logrus#level-logging - Trace, Debug, Info, Warning, Error, Fatal and Panic. Default log level is `Info`.