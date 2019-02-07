DOCKER_IMAGE = dokken.azurecr.io/azure-keyvault-controller
DOCKER_TAG 	 = $(shell git rev-parse --short HEAD)
GOPACKAGES = $(shell go list ./... | grep -v /pkg/)

build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

test:
	CGO_ENABLED=0 go test -v $(GOPACKAGES)

push:
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
