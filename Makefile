PACKAGE=github.com/SparebankenVest/azure-key-vault-to-kubernetes

DOCKER_INTERNAL_HOST=dokken.azurecr.io
DOCKER_RELEASE_HOST=spvest

DOCKER_CONTROLLER_IMAGE=azure-keyvault-controller
DOCKER_WEBHOOK_IMAGE=azure-keyvault-webhook
DOCKER_VAULTENV_IMAGE=azure-keyvault-env

DOCKER_TAG := $(shell git rev-parse --short HEAD)
DOCKER_RELEASE_TAG := $(shell git describe)

GOPACKAGES := $(shell go list ./... | grep -v /pkg/)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_URL := https://$(PACKAGE)

.PHONY: build build-controller build-webhook build-vaultenv test push push-controller push-webhook push-vaultenv pull-release tag-release push-release

build: build-controller build-webhook build-vaultenv

build-controller:
	docker build . -t $(DOCKER_INTERNAL_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_TAG) -f Dockerfile --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-controller" --build-arg VCS_REF=$(DOCKER_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)

build-webhook:
	docker build . -t $(DOCKER_INTERNAL_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_TAG) -f Dockerfile.webhook --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-secrets-webhook" --build-arg VCS_REF=$(DOCKER_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)
	
build-vaultenv:
	docker build . -t $(DOCKER_INTERNAL_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_TAG) -f Dockerfile.vaultenv --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-env" --build-arg VCS_REF=$(DOCKER_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)

test:
	CGO_ENABLED=0 go test -v $(GOPACKAGES)

push: push-controller push-webhook push-vaultenv

push-controller:
	docker push $(DOCKER_INTERNAL_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_TAG)

push-webhook:
	docker push $(DOCKER_INTERNAL_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_TAG)

push-vaultenv:
	docker push $(DOCKER_INTERNAL_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_TAG)

pull-release:
	docker pull $(DOCKER_INTERNAL_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_TAG) 
	docker pull $(DOCKER_INTERNAL_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_TAG) 
	docker pull $(DOCKER_INTERNAL_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_TAG) 

tag-release:
	docker tag $(DOCKER_INTERNAL_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG)
	docker tag $(DOCKER_INTERNAL_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_HOST)/$(DOCKER_CONTROLLER_IMAGE):latest
	
	docker tag $(DOCKER_INTERNAL_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_RELEASE_TAG)
	docker tag $(DOCKER_INTERNAL_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_HOST)/$(DOCKER_WEBHOOK_IMAGE):latest
	
	docker tag $(DOCKER_INTERNAL_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_RELEASE_TAG)
	docker tag $(DOCKER_INTERNAL_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_HOST)/$(DOCKER_VAULTENV_IMAGE):latest

push-release:
	docker push $(DOCKER_RELEASE_HOST)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG)
	docker push $(DOCKER_RELEASE_HOST)/$(DOCKER_CONTROLLER_IMAGE):latest
	
	docker push $(DOCKER_RELEASE_HOST)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_RELEASE_TAG)
	docker push $(DOCKER_RELEASE_HOST)/$(DOCKER_WEBHOOK_IMAGE):latest
	
	docker push $(DOCKER_RELEASE_HOST)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_RELEASE_TAG)
	docker push $(DOCKER_RELEASE_HOST)/$(DOCKER_VAULTENV_IMAGE):latest
