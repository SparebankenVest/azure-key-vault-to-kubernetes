# Accept the Go version for the image to be set as a build argument.
# Default to Go 1.11.5
ARG GO_VERSION=1.11.5
ARG DEP_VERSION=v0.5.0
ARG VCS_REF
ARG BUILD_DATE
ARG VCS_URL

# First stage: build the executable.
FROM golang:${GO_VERSION}-alpine AS build

# Create the user and group files that will be used in the running container to
# run the process as an unprivileged user.
RUN mkdir /user && \
    echo 'nobody:x:65534:65534:nobody:/:' > /user/passwd && \
    echo 'nobody:x:65534:' > /user/group

ARG PACKAGE=github.com/SparebankenVest/azure-keyvault-controller

ENV DEP_RELEASE_TAG=${DEP_VERSION}
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

RUN mkdir -p /go/src/${PACKAGE}
WORKDIR /go/src/${PACKAGE}

COPY Gopkg.* /go/src/${PACKAGE}/
RUN dep ensure --vendor-only

COPY . /go/src/${PACKAGE}
RUN CGO_ENABLED=0 go install ./cmd/azure-keyvault-controller 

FROM alpine:3.8

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.url=$VCS_URL
LABEL org.label-schema.description="A Kubernetes controller to sync Azure Key Vault objects as secrets in Kubernetes"
LABEL org.label-schema.vendor="Sparebanken Vest"      
LABEL org.label-schema.author="Jon Arild Tørresdal"

RUN addgroup -g 1000 -S akvcontroller && \
    adduser -u 1000 -S akvcontroller -G akvcontroller

# install without cache
RUN apk update && apk add --no-cache \
    ca-certificates \
    iptables \
    && update-ca-certificates

COPY --from=build /go/bin/azure-keyvault-controller /usr/local/bin/azure-keyvault-controller

USER akvcontroller
ENTRYPOINT ["azure-keyvault-controller"]
