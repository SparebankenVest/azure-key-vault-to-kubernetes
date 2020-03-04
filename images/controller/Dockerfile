FROM spvest/golang-build-stage:1.13.0 as build

FROM alpine:3.8

ARG VCS_REF
ARG BUILD_DATE
ARG VCS_URL

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes controller to sync Azure Key Vault objects as secrets in Kubernetes"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

# install without cache
RUN apk update && apk add --no-cache \
    ca-certificates \
    iptables \
    && update-ca-certificates

COPY --from=build /go/bin/azure-keyvault-controller /usr/local/bin/azure-keyvault-controller

ENTRYPOINT ["azure-keyvault-controller"]
