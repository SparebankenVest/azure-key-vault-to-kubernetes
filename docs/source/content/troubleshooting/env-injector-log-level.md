---
title: "Set env-injector log-level"
description: "How to set the log-level for the env-injector"
---

The Env-Injector logs in three different places:

* The Pod hosting the Webhook
* The init-container
* During startup of container where environment variables are injected

## Access Webhook logs

The Webhook logs information about every Pod that attempts to start in a namespace monitored by the Env-Injector. If something goes wrong during the mutation of a Pod, the log will contain information about what happened. If you want more detailed information, you can increase the log level.

Log level is controlled through the environment variable `LOG_LEVEL` on the webhook container or through the `logLevel` parameter for the Env-Injector Helm Chart.

## Access init-container logs

The init-container will only execute shell commands for copying files into the in-memory volume at `/azure-keyvault/` - but if that would fail, the init-container will contain the shell output in its log.

## Access logs in your own container

During startup of a container where environment variables are injected, the `azure-keyvault-env` executable will output any errors that occured during injection and debug messages. To see any debug message, the log level must be set to `debug`.

Debug level is controlled through the environment variable `ENV_INJECTOR_LOG_LEVEL` on your container.

The env-injector uses Logrus for logging, supporting seven log levels: https://github.com/Sirupsen/logrus#level-logging - Trace, Debug, Info, Warning, Error, Fatal and Panic. Default log level is `Info`.