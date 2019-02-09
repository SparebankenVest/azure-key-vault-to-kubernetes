DOCKER_IMAGE = dokken.azurecr.io/azure-keyvault-controller
DOCKER_TAG 	 = $(shell git rev-parse --short HEAD)
DOCKER_RELEASE_IMAGE = spvest/azure-keyvault-controller
DOCKER_RELEASE_TAG 	 = $(shell git describe)
GOPACKAGES = $(shell go list ./... | grep -v /pkg/)
BUILD_DATE = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_URL = https://github.com/SparebankenVest/azure-keyvault-controller

build:
	docker build --build-arg VCS_REF=$(DOCKER_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL) -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

test:
	CGO_ENABLED=0 go test -v $(GOPACKAGES)

push:
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

pull-release:
	docker pull $(DOCKER_IMAGE):$(DOCKER_TAG) 

tag-release:
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_IMAGE):$(DOCKER_RELEASE_TAG)
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_IMAGE):latest

push-release:
	docker push $(DOCKER_RELEASE_IMAGE):$(DOCKER_RELEASE_TAG)
	docker push $(DOCKER_RELEASE_IMAGE):latest
