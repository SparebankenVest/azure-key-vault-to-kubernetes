PACKAGE=github.com/SparebankenVest/azure-key-vault-to-kubernetes

KUBERNETES_VERSION=v1.17.9
KUBERNETES_DEP_VERSION=v0.17.9

DOCKER_INTERNAL_REG=dokken.azurecr.io
DOCKER_RELEASE_REG=spvest

DOCKER_CONTROLLER_IMAGE=azure-keyvault-controller
DOCKER_CA_BUNDLE_CONTROLLER_IMAGE=ca-bundle-controller
DOCKER_WEBHOOK_IMAGE=azure-keyvault-webhook
DOCKER_AUTH_SERVICE_IMAGE=azure-keyvault-auth-service
DOCKER_VAULTENV_IMAGE=azure-keyvault-env
DOCKER_AKV2K8S_TEST_IMAGE=akv2k8s-env-test

DOCKER_INTERNAL_TAG := $(shell git rev-parse --short HEAD)
DOCKER_RELEASE_TAG := $(shell git describe --tags)
DOCKER_RELEASE_TAG_WEBHOOK := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"webhook-"/""/g)
DOCKER_RELEASE_TAG_CONTROLLER := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"controller-"/""/g)
DOCKER_RELEASE_TAG_VAULTENV := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"vaultenv-"/""/g)
DOCKER_RELEASE_TAG_CA_BUNDLE_CONTROLLER := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"ca-bundle-controller-"/""/g)

BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_URL := https://$(PACKAGE)

.PHONY: run-docs-dev build build-controller build-webhook build-auth-service build-vaultenv build-akv2k8s-env-test test push push-controller push-webhook push-auth-service push-vaultenv push-akv2k8s-env-test pull-release release release-controller release-webhook release-auth-service release-vaultenv

print-v-webhook:
	@echo $(DOCKER_RELEASE_TAG_WEBHOOK) 

print-v-controller:
	@echo $(DOCKER_RELEASE_TAG_CONTROLLER) 

print-v-vaultenv:
	@echo $(DOCKER_RELEASE_TAG_VAULTENV) 

print-v-ca-bundle-controller:
	@echo $(DOCKER_RELEASE_TAG_CA_BUNDLE_CONTROLLER) 

docs-install-dev:
	cd ./docs && npm install

docs-run-dev:
	cd ./docs && GATSBY_ALGOLIA_ENABLED=false npm run start

fmt:
	@echo "==> Fixing source code with gofmt..."
	# This logic should match the search logic in scripts/gofmtcheck.sh
	find . -name '*.go' | grep -v /pkg/k8s/ | xargs gofmt -s -w

fmtcheck:
	$(CURDIR)/scripts/gofmtcheck.sh

codegen:
	@echo "Making sure code-generator has correct version of Kubernetes ($(KUBERNETES_DEP_VERSION))"
	@echo ""
	rm -rf ${GOPATH}/src/k8s.io/code-generator
	git clone --depth 1 --branch $(KUBERNETES_DEP_VERSION) git@github.com:kubernetes/code-generator.git ${GOPATH}/src/k8s.io/code-generator
	./hack/update-codegen.sh

test: fmtcheck
	CGO_ENABLED=0 go test -v $(shell go list ./... | grep -v /pkg/k8s/)

build-local: fmtcheck
	CGO_ENABLED=0 go build -v $(shell go list ./...)

build: build-controller build-ca-bundle-controller build-webhook build-vaultenv

build-controller:
	docker build . -t $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) -f images/controller/Dockerfile --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-controller" --build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)

build-ca-bundle-controller:
	docker build . -t $(DOCKER_INTERNAL_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) -f images/ca-bundle-controller/Dockerfile --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/ca-bundle-controller" --build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)

build-webhook:
	docker build . -t $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) -f images/env-injector/Dockerfile --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-secrets-webhook" --build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)

build-vaultenv:
	docker build . -t $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) -f images/vault-env/Dockerfile --build-arg PACKAGE=$(PACKAGE) --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-env" --build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_URL=$(VCS_URL)

build-akv2k8s-env-test:
	docker build . -t $(DOCKER_RELEASE_REG)/$(DOCKER_AKV2K8S_TEST_IMAGE) -f images/akv2k8s-test/Dockerfile

push: push-controller push-ca-bundle-controller push-webhook push-vaultenv

push-controller:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG)

push-ca-bundle-controller:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG)

push-webhook:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG)

push-auth-service:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_AUTH_SERVICE_IMAGE):$(DOCKER_INTERNAL_TAG)

push-vaultenv:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG)

push-akv2k8s-env-test:
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_AKV2K8S_TEST_IMAGE)

pull-all: pull-webhook pull-controller pull-ca-bundle-controller pull-vaultenv

pull-webhook:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) 

pull-controller:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) 

pull-ca-bundle-controller:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) 

pull-vaultenv:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) 

release: release-controller release-ca-bundle-controller release-webhook release-vaultenv

release-controller:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG_CONTROLLER)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG_CONTROLLER)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):latest

release-ca-bundle-controller:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG_CA_BUNDLE_CONTROLLER)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG_CA_BUNDLE_CONTROLLER)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_CA_BUNDLE_CONTROLLER_IMAGE):latest

release-webhook:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_RELEASE_TAG_WEBHOOK)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_RELEASE_TAG_WEBHOOK)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):latest

release-vaultenv:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_RELEASE_TAG_VAULTENV)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_RELEASE_TAG_VAULTENV)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):latest

# define release_image
# 	docker pull $(DOCKER_INTERNAL_REG)/$(1):$(DOCKER_INTERNAL_TAG)
# 	docker tag $(DOCKER_INTERNAL_REG)/$(1):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(1):$(DOCKER_RELEASE_TAG)
# 	docker tag $(DOCKER_INTERNAL_REG)/$(1):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(1):latest
# 	docker push $(DOCKER_RELEASE_REG)/$(1):$(DOCKER_RELEASE_TAG)
# 	docker push $(DOCKER_RELEASE_REG)/$(1):latest
# endef