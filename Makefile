DOCKER_IMAGE = dokken.azurecr.io/azure-keyvault-controller
DOCKER_TAG 	 = $(shell git rev-parse --short HEAD)

build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

push:
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
