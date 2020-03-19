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
LABEL org.label-schema.description="A Azure auth service that provides oauth tokens to env-injector"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

RUN apk add --update libcap && rm -rf /var/cache/apk/*

COPY --from=build /go/bin/azure-keyvault-auth-service /usr/local/bin/azure-keyvault-auth-service
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/usr/local/bin/azure-keyvault-auth-service"]