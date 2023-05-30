FROM golang:1.20-alpine

ENV GO111MODULE=on
ENV XDG_CACHE_HOME /tmp/.cache
ENV GOPATH /tmp/go
ENV GOBIN /tmp/gobin

ARG KUBERNETES_VERSION="v0.26.5"
ARG REPO="${GOPATH}/src/github.com/SparebankenVest/azure-key-vault-to-kubernetes"

RUN apk add --no-cache bash git openssh \
  && git clone --depth 1 --branch ${KUBERNETES_VERSION} \
  https://github.com/kubernetes/code-generator.git ${GOPATH}/src/k8s.io/code-generator

RUN cd ${GOPATH}/src/k8s.io/code-generator \
  && go mod download \
  && mkdir -p ${GOBIN} \
  && mkdir -p ${REPO} \
  && find ${GOPATH} -type d -exec chmod 755 {} \; \
  && find ${GOPATH} -type f -exec chmod 666 {} \; \
  && chmod +x ${GOPATH}/src/k8s.io/code-generator/generate-groups.sh \
  && chmod +x ${GOPATH}/src/k8s.io/code-generator/generate-internal-groups.sh

WORKDIR ${REPO}

VOLUME ${REPO}
