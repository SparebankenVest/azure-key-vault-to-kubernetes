ARG BASEIMAGE=gcr.io/distroless/static:nonroot
ARG BASE_ALPINE=alpine:3.15.4
ARG GO_VERSION=1.18.1

# -------
# Builder
# -------
FROM golang:${GO_VERSION} AS base_builder
ARG PACKAGE

WORKDIR /go/src/${PACKAGE}
ADD go.mod go.sum /go/src/${PACKAGE}
RUN go mod download

FROM base_builder AS builder
ARG PACKAGE
ARG VCS_REF=noref
ARG BUILD_SUB_TARGET

WORKDIR /go/src/${PACKAGE}

ADD . .
RUN GIT_TAG=${VCS_REF} make build${BUILD_SUB_TARGET}

# ------------
# Env Injector
# ------------
FROM $BASE_ALPINE AS webhook
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
ENTRYPOINT ["/usr/local/bin/azure-keyvault-secrets-webhook"]

# ----------
# Controller
# ----------
FROM $BASE_ALPINE AS controller
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
ENTRYPOINT ["/usr/local/bin/azure-keyvault-controller"]

# --------
# vaultenv
# --------
FROM $BASE_ALPINE AS vaultenv
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
