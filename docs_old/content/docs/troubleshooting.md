---
title: "Troubleshooting"
metaTitle: "Troubleshooting"
metaDescription: "Tips and trick for how to troubleshoot Azure Key Vault to Kubernetes."
index: 90
---

## Increase env-injector log-level on your Pod

If everything looks OK in the env-injector Pod, it is possible to set the env-variable `ENV_INJECTOR_LOG_LEVEL` on your Pod, allowing you to see detailed logging of what's going on during secret injection and startup of your Pod. 

The env-injector uses Logrus for logging, supporting seven log levels: https://github.com/Sirupsen/logrus#level-logging - Trace, Debug, Info, Warning, Error, Fatal and Panic. Default log level is `Info`.