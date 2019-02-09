DOCKER_IMAGE = dokken.azurecr.io/azure-keyvault-controller
DOCKER_TAG 	 = $(shell git rev-parse --short HEAD)
DOCKER_RELEASE_IMAGE = spvest/azure-keyvault-controller
DOCKER_RELEASE_TAG 	 = $(shell git describe)
GOPACKAGES = $(shell go list ./... | grep -v /pkg/)

build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

test:
	CGO_ENABLED=0 go test -v $(GOPACKAGES)

push:
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

pull-release:
	docker pull $(DOCKER_IMAGE):$(DOCKER_TAG) 

tag-release:
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_RELEASE_IMAGE):$(DOCKER_RELEASE_TAG)

push-release:
	docker push $(DOCKER_RELEASE_IMAGE):$(DOCKER_RELEASE_TAG)
