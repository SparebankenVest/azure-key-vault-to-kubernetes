---
title: "Known Issues"
description: "A list of known issues and available solutions or workarounds"
---

## Env Injector - x509: certificate signed by unknown authority

**Issue:** Trying to inject secrets into a application running on a container without CA certificates will fail with an error like below:

```bash
level=fatal msg="env-injector: failed to read secret 'test', error azure.BearerAuthorizer#WithAuthorization: Failed to refresh the Token for request to https://my-key-vault.vault.azure.net/secrets/test/?api-version=2016-10-01: StatusCode=0 -- Original Error: adal: Failed to execute the refresh request. Error = 'Post https://login.microsoftonline.com/xxx/oauth2/token?api-version=1.0: x509: certificate signed by unknown authority'"
```

Doing HTTPS calls without CA certificates will make it impossible for the client to validate if a TLS certificate is signed by a trusted CA.

**Solution:** Make sure CA certificates are installed in the Docker image used by the container you are trying to inject env vars into (eg. `apt-get install -y ca-certificates`)

## Env injector - failed calling webhook

**Issue:** Trying to install the Env Injector in the same namespace as you intend to use it might fail with:

```bash
Error creating: Internal error occurred: failed calling webhook "pods.azure-key-vault-env-injector.admission.spv.no": Post https://azure-key-vault-env-injector.some-namespace.svc:443/pods?timeout=30s: dial tcp 10.1.1.124:443: connect: connection refused
```

**Solution:** Make sure to install Env Injector into its own dedicated namespace, and NOT label namespace with `azure-key-vault-env-injection: enabled`. This label is ONLY intended for namespaces where Env Injector is going to inject secrets, not where Env Injector is installed.