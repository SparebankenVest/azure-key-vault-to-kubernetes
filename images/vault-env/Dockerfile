FROM spvest/golang-build-stage:1.13.0 as build

FROM alpine:3.8

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="An executable to transparantly inject Azure Key Vault secrets into a container as environment variables"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

COPY --from=build /go/bin/azure-keyvault-env /usr/local/bin/azure-keyvault-env