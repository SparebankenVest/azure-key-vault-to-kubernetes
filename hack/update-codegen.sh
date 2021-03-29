#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

HACK_DIR="$(dirname ${BASH_SOURCE})"
REPO_DIR="${HACK_DIR}/.."

PROJECT_MODULE="github.com/SparebankenVest/azure-key-vault-to-kubernetes"
IMAGE_NAME="kubernetes-codegen:latest"

echo "Building codegen Docker image..."
docker build -f "${HACK_DIR}/Dockerfile" \
  -t "${IMAGE_NAME}" \
  "${REPO_DIR}"

CMD="/tmp/go/src/k8s.io/code-generator/generate-groups.sh deepcopy,client,informer,lister \
  "${PROJECT_MODULE}/pkg/k8s/client" \
  "${PROJECT_MODULE}/pkg/k8s/apis" \
  "azurekeyvault:v1alpha1,v1,v2alpha1,v2beta1" \
  --go-header-file /tmp/go/src/${PROJECT_MODULE}/hack/custom-boilerplate.go.txt"

echo "Generating client codes..."
echo "$CMD"
docker run --rm \
  -v "$(readlink -e ${REPO_DIR}):/tmp/go/src/${PROJECT_MODULE}" \
  "${IMAGE_NAME}" $CMD

sudo chown ${USER}:${USER} -R ${REPO_DIR}/pkg/k8s
