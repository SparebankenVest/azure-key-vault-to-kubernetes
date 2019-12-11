---
title: "Known Issues"
metaTitle: "Known Issues"
metaDescription: "A list of known issues and available solutions or workarounds"
index: 100
---

### Env Injector - x509: certificate signed by unknown authority

**Issue:** Trying to inject secrets into a application running on a container without CA certificates will fail with an error like below:

`level=fatal msg="env-injector: failed to read secret 'test', error azure.BearerAuthorizer#WithAuthorization: Failed to refresh the Token for request to https://my-key-vault.vault.azure.net/secrets/test/?api-version=2016-10-01: StatusCode=0 -- Original Error: adal: Failed to execute the refresh request. Error = 'Post https://login.microsoftonline.com/xxx/oauth2/token?api-version=1.0: x509: certificate signed by unknown authority'"`

Doing HTTPS calls without CA certificates will make it impossible for the client to validate if a TLS certificate is signed by a trusted CA.

**Solution:** Make sure CA certificates are installed in the Docker image used by the container you are trying to inject env vars into (eg. `apt-get install -y ca-certificates`)
