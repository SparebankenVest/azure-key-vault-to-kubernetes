# Accept the Go version for the image to be set as a build argument.
# Default to Go 1.11.5
ARG GO_VERSION=1.11.5
ARG DEP_VERSION=v0.5.0

# First stage: build the executable.
FROM golang:${GO_VERSION}-alpine AS build

# Create the user and group files that will be used in the running container to
# run the process as an unprivileged user.
RUN mkdir /user && \
    echo 'nobody:x:65534:65534:nobody:/:' > /user/passwd && \
    echo 'nobody:x:65534:' > /user/group

RUN mkdir -p /go/src/github.com/SparebankenVest/azure-keyvault-controller
WORKDIR /go/src/github.com/SparebankenVest/azure-keyvault-controller

# Import the code from the context.
COPY ./ ./

# Build the executable to `/app`. Mark the build as statically linked.
RUN CGO_ENABLED=0 go build \
    -installsuffix 'static' \
-o ./bin/azure-keyvault-controller . 

FROM alpine:3.8
MAINTAINER Jon Arild Tørresddal <jon.torresdal@spv.no>

# install without cache
RUN apk update && apk add --no-cache \
    ca-certificates \
    iptables \
    && update-ca-certificates

COPY --from=build /go/src/github.com/SparebankenVest/azure-keyvault-controller/bin/azure-keyvault-controller /bin/azure-keyvault-controller

ENTRYPOINT ["azure-keyvault-controller"]
