ARG BASEIMAGE=gcr.io/distroless/static:nonroot
ARG BASE_ALPINE=alpine:3.8
ARG GO_VERSION=1.13.0

# -------
# Builder
# -------
FROM golang:${GO_VERSION} AS builder
ARG PACKAGE
ARG BUILD_SUB_TARGET
WORKDIR /go/src/${PACKAGE}
ADD . .
RUN go mod download
RUN make build${BUILD_SUB_TARGET}

# ------------
# Env Injector
# ------------
FROM $BASEIMAGE AS webhook
ARG VCS_REF
ARG BUILD_DATE
ARG VCS_URL
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes Mutating Admission Webhook that adds an init container to a pod that will inject environment variables from Azure Key Vault"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

COPY --from=builder /go/src/github.com/SparebankenVest/azure-key-vault-to-kubernetes/bin/azure-key-vault-to-kubernetes/azure-keyvault-secrets-webhook /usr/local/bin/
ENV DEBUG false
USER 65534
ENTRYPOINT ["/usr/local/bin/azure-keyvault-secrets-webhook"]

# ----------
# Controller
# ----------
FROM $BASEIMAGE AS controller
ARG VCS_REF
ARG BUILD_DATE
ARG VCS_URL
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes Mutating Admission Webhook that adds an init container to a pod that will inject environment variables from Azure Key Vault"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

COPY --from=builder /go/src/github.com/SparebankenVest/azure-key-vault-to-kubernetes/bin/azure-key-vault-to-kubernetes/azure-keyvault-controller /usr/local/bin/
ENV DEBUG false
USER 65534
ENTRYPOINT ["/usr/local/bin/azure-keyvault-controller"]

# --------------------
# CA Bundle Controller
# --------------------
FROM $BASEIMAGE AS ca-bundle-controller
ARG VCS_REF
ARG BUILD_DATE
ARG VCS_URL
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes Mutating Admission Webhook that adds an init container to a pod that will inject environment variables from Azure Key Vault"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

COPY --from=builder /go/src/github.com/SparebankenVest/azure-key-vault-to-kubernetes/bin/azure-key-vault-to-kubernetes/ca-bundle-controller /usr/local/bin/
ENV DEBUG false
USER 65534
ENTRYPOINT ["/usr/local/bin/azure-keyvault-secrets-webhook"]

# --------
# vaultenv
# --------
FROM $BASEIMAGE AS vaultenv
ARG VCS_REF
ARG BUILD_DATE
ARG VCS_URL
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes Mutating Admission Webhook that adds an init container to a pod that will inject environment variables from Azure Key Vault"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

COPY --from=builder /go/src/github.com/SparebankenVest/azure-key-vault-to-kubernetes/bin/azure-key-vault-to-kubernetes/azure-keyvault-env /usr/local/bin/
ENV DEBUG false
USER 65534
