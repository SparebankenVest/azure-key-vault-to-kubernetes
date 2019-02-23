PACKAGE=github.com/SparebankenVest/azure-key-vault-to-kubernetes

# DOCKER_HOST=dokken.azurecr.io
# DOCKER_RELEASE_HOST=spvest

# DOCKER_CONTROLLER_IMAGE=azure-keyvault-controller
# DOCKER_WEBHOOK_IMAGE=azure-keyvault-webhook
# DOCKER_VAULTENV_IMAGE=azure-keyvault-env

# DOCKER_TAG := $(shell git rev-parse --short HEAD)
# DOCKER_RELEASE_TAG := $(shell git describe)

# GOPACKAGES := $(shell go list ./... | grep -v /pkg/)
# BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
# VCS_URL := https://$(PACKAGE)

build:
	docker build . -t $(DOCKER_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_TAG) -f Dockerfile --build-arg PACKAGE=github.com/SparebankenVest/azure-key-vault-to-kubernetes --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-controller" --build-arg VCS_REF=f3e10b2 --build-arg BUILD_DATE=2019-02-23T21:17:16Z --build-arg VCS_URL=https://github.com/SparebankenVest/azure-key-vault-to-kubernetes
