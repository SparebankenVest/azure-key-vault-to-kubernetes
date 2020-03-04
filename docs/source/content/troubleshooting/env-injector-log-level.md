---
title: "Set env-injector log-level"
description: "How to set the log-level for the env-injector"
---

It is possible to set the env-variable `ENV_INJECTOR_LOG_LEVEL` on your Pod, allowing you to see detailed logging of what's going on during secret injection and startup of your Pod. 

The env-injector uses Logrus for logging, supporting seven log levels: https://github.com/Sirupsen/logrus#level-logging - Trace, Debug, Info, Warning, Error, Fatal and Panic. Default log level is `Info`.