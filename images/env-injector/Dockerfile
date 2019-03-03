FROM spvest/golang-build-stage as build

FROM alpine:3.8

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes Mutating Admission Webhook that adds an init container to a pod that will inject environment variables from Azure Key Vault"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

RUN apk add --update libcap && rm -rf /var/cache/apk/*

COPY --from=build /go/bin/azure-keyvault-secrets-webhook /usr/local/bin/azure-keyvault-secrets-webhook
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# RUN adduser -D azure-keyvault-secrets-webhook
# RUN setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/azure-keyvault-secrets-webhook
# USER azure-keyvault-secrets-webhook

ENV DEBUG false

ENTRYPOINT ["/usr/local/bin/azure-keyvault-secrets-webhook"]