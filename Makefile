ORG_PATH=github.com/SparebankenVest
PROJECT_NAME := azure-key-vault-to-kubernetes
PACKAGE=$(ORG_PATH)/$(PROJECT_NAME)

COMPONENT_VAR=$(PACKAGE)/pkg/akv2k8s.Component
GIT_VAR=$(PACKAGE)/pkg/akv2k8s.GitCommit
BUILD_DATE_VAR := $(PACKAGE)/pkg/akv2k8s.BuildDate

WEBHOOK_BINARY_NAME=azure-keyvault-secrets-webhook
CONTROLLER_BINARY_NAME=azure-keyvault-controller
KEYVAULT_ENV_BINARY_NAME=azure-keyvault-env

DOCKER_INTERNAL_REG=dokken.azurecr.io
DOCKER_RELEASE_REG=spvest

DOCKER_CONTROLLER_IMAGE=azure-keyvault-controller
DOCKER_WEBHOOK_IMAGE=azure-keyvault-webhook
DOCKER_AUTH_SERVICE_IMAGE=azure-keyvault-auth-service
DOCKER_VAULTENV_IMAGE=azure-keyvault-env
DOCKER_AKV2K8S_TEST_IMAGE=akv2k8s-env-test

DOCKER_INTERNAL_TAG := $(shell git rev-parse --short HEAD)
DOCKER_RELEASE_TAG := $(shell git describe --tags)
DOCKER_RELEASE_TAG_WEBHOOK := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"webhook-"/""/g)
DOCKER_RELEASE_TAG_CONTROLLER := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"controller-"/""/g)
DOCKER_RELEASE_TAG_VAULTENV := $(shell echo $(DOCKER_RELEASE_TAG) | sed s/"vaultenv-"/""/g)

TAG=
GOOS ?= linux
TEST_GOOS ?= linux

BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_URL := https://$(PACKAGE)

TOOLS_MOD_DIR := ./tools
TOOLS_DIR := $(abspath ./.tools)
CRDS_DIR := $(abspath ./crds)

ifeq ($(OS),Windows_NT)
	GO_BUILD_MODE = default
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S), Linux)
		GO_BUILD_MODE = pie
	endif
	ifeq ($(UNAME_S), Darwin)
		GO_BUILD_MODE = default
	endif
endif

##asdf

GO_BUILD_OPTIONS := --tags "netgo osusergo" -ldflags "-s -X $(COMPONENT_VAR)=$(COMPONENT) -X $(GIT_VAR)=$(GIT_TAG) -X $(BUILD_DATE_VAR)=$(BUILD_DATE) -extldflags '-static'"

$(TOOLS_DIR)/golangci-lint: $(TOOLS_MOD_DIR)/go.mod $(TOOLS_MOD_DIR)/go.sum $(TOOLS_MOD_DIR)/tools.go
	cd $(TOOLS_MOD_DIR) && \
	go build -o $(TOOLS_DIR)/golangci-lint github.com/golangci/golangci-lint/cmd/golangci-lint

$(TOOLS_DIR)/misspell: $(TOOLS_MOD_DIR)/go.mod $(TOOLS_MOD_DIR)/go.sum $(TOOLS_MOD_DIR)/tools.go
	cd $(TOOLS_MOD_DIR) && \
	go build -o $(TOOLS_DIR)/misspell github.com/client9/misspell/cmd/misspell

$(TOOLS_DIR)/controller-gen: $(TOOLS_MOD_DIR)/go.mod $(TOOLS_MOD_DIR)/go.sum $(TOOLS_MOD_DIR)/tools.go
	cd $(TOOLS_MOD_DIR) && \
	go build -o $(TOOLS_DIR)/controller-gen sigs.k8s.io/controller-tools/cmd/controller-gen

.PHONY: precommit
precommit: build test lint

.PHONY: mod
mod:
	@go mod tidy

.PHONY: check-vendor
check-mod: mod
	@git diff --exit-code go.mod go.sum

.PHONY: lint
lint: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/misspell
	$(TOOLS_DIR)/golangci-lint run --timeout=5m && \
	find . -type f \( -iname \*.go -o -iname \*.md \) | xargs $(TOOLS_DIR)/misspell -w && \
	go mod tidy

.PHONY: print-v-webhook
print-v-webhook:
	@echo $(DOCKER_RELEASE_TAG_WEBHOOK)

.PHONY: print-v-controller
print-v-controller:
	@echo $(DOCKER_RELEASE_TAG_CONTROLLER)

.PHONY: print-v-vaultenv
print-v-vaultenv:
	@echo $(DOCKER_RELEASE_TAG_VAULTENV)

.PHONY: tag-all
tag-all: tag-webhook tag-controller tag-vaultenv

.PHONY: tag-crd
tag-crd: check-tag
	git tag -a crd-$(TAG) -m "CRD version $(TAG)"
	git push --tags

.PHONY: tag-webhook
tag-webhook: check-tag
	git tag -a webhook-$(TAG) -m "Webhook version $(TAG)"
	git push --tags

.PHONY: tag-controller
tag-controller: check-tag
	git tag -a controller-$(TAG) -m "Controller version $(TAG)"
	git push --tags

.PHONY: tag-vaultenv
tag-vaultenv: check-tag
	git tag -a vaultenv-$(TAG) -m "Vaultenv version $(TAG)"
	git push --tags

.PHONY: check-tag
check-tag:
ifndef TAG
	$(error TAG is undefined)
endif

.PHONY: fmt
fmt:
	@echo "==> Fixing source code with gofmt..."
	# This logic should match the search logic in scripts/gofmtcheck.sh
	find . -name '*.go' | grep -v /pkg/k8s/ | xargs gofmt -s -w

.PHONY: fmtcheck
fmtcheck:
	$(CURDIR)/scripts/gofmtcheck.sh

.PHONY: codegen
codegen:
	./hack/update-codegen.sh

.PHONY: crdgen
crdgen: $(TOOLS_DIR)/controller-gen
	$(TOOLS_DIR)/controller-gen \
		crd:crdVersions=v1 \
  		paths=./pkg/k8s/apis/azurekeyvault/v1alpha1/... \
  		paths=./pkg/k8s/apis/azurekeyvault/v1/... \
  		paths=./pkg/k8s/apis/azurekeyvault/v2alpha1/... \
  		paths=./pkg/k8s/apis/azurekeyvault/v2beta1/... \
  		output:crd:artifacts:config=./crds
	mv $(CRDS_DIR)/spv.no_azurekeyvaultsecrets.yaml $(CRDS_DIR)/AzureKeyVaultSecret.yaml

.PHONY: test
test: fmtcheck
	GOOS=$(TEST_GOOS) \
	CGO_ENABLED=0 \
	AKV2K8S_CLIENT_ID=$(AKV2K8S_CLIENT_ID) \
	AKV2K8S_CLIENT_SECRET=$(AKV2K8S_CLIENT_SECRET) \
	AKV2K8S_CLIENT_TENANT_ID=$(AKV2K8S_CLIENT_TENANT_ID) \
	AKV2K8S_AZURE_SUBSCRIPTION_ID=$(AKV2K8S_AZURE_SUBSCRIPTION_ID) \
	go test -coverprofile=coverage.txt -covermode=atomic -count=1 -v $(shell go list ./... | grep -v /pkg/k8s/)

.PHONY: init-int-test-local
init-int-test-local:
	$(eval AKV2K8S_CLIENT_ID ?= $(shell az keyvault secret show --name int-test-azure-client-id --vault-name akv2k8s-test --subscription $(AKV2K8S_AZURE_SUBSCRIPTION_ID) --output tsv --query 'value'))
	$(eval AKV2K8S_CLIENT_SECRET ?= $(shell az keyvault secret show --name int-test-azure-client-secret --vault-name akv2k8s-test --subscription $(AKV2K8S_AZURE_SUBSCRIPTION_ID) --output tsv --query 'value'))
	$(eval AKV2K8S_CLIENT_TENANT_ID ?= $(shell az keyvault secret show --name int-test-azure-tenant-id --vault-name akv2k8s-test --subscription $(AKV2K8S_AZURE_SUBSCRIPTION_ID) --output tsv --query 'value'))

.PHONY: int-test-local
int-test-local: init-int-test-local test

bin/%:
	GOOS=$(GOOS) GOARCH=amd64 go build $(GO_BUILD_OPTIONS) -o "$(@)" "$(PKG_NAME)"

.PHONY: clean
clean:
	rm -rf bin/$(PROJECT_NAME)

.PHONY: clean-webhook
clean-webhook:
	rm -rf bin/$(PROJECT_NAME)/$(WEBHOOK_BINARY_NAME)

.PHONY: clean-controller
clean-controller:
	rm -rf bin/$(PROJECT_NAME)/$(CONTROLLER_BINARY_NAME)

.PHONY: clean-vaultenv
clean-vaultenv:
	rm -rf bin/$(PROJECT_NAME)/$(KEYVAULT_ENV_BINARY_NAME)

# build: build-controller build-webhook build-vaultenv
.PHONY: build
build: clean build-webhook build-controller build-vaultenv

.PHONY: build-webhook
build-webhook: clean-webhook
	CGO_ENABLED=0 COMPONENT=webhook PKG_NAME=$(PACKAGE)/cmd/$(WEBHOOK_BINARY_NAME) $(MAKE) bin/$(PROJECT_NAME)/$(WEBHOOK_BINARY_NAME)

.PHONY: build-controller
build-controller: clean-controller
	CGO_ENABLED=0 COMPONENT=controller PKG_NAME=$(PACKAGE)/cmd/$(CONTROLLER_BINARY_NAME) $(MAKE) bin/$(PROJECT_NAME)/$(CONTROLLER_BINARY_NAME)

.PHONY: build-vaultenv
build-vaultenv: clean-vaultenv
	CGO_ENABLED=0 COMPONENT=vaultenv PKG_NAME=$(PACKAGE)/cmd/$(KEYVAULT_ENV_BINARY_NAME) $(MAKE) bin/$(PROJECT_NAME)/$(KEYVAULT_ENV_BINARY_NAME)

.PHONY: images
images: image-webhook image-controller image-vaultenv

.PHONY: upload-kind-webhook
upload-kind-webhook:
	kind load docker-image $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: upload-kind-controller
upload-kind-controller:
	kind load docker-image $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: upload-kind-vaultenv
upload-kind-vaultenv:
	kind load docker-image $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: image-webhook
image-webhook:
	DOCKER_BUILDKIT=1 docker build \
		--progress=plain \
		--target webhook \
		--build-arg BUILD_SUB_TARGET="-webhook" \
		--build-arg PACKAGE=$(PACKAGE) \
		--build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg VCS_URL=$(VCS_URL) \
		-t $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) .

.PHONY: image-controller
image-controller:
	DOCKER_BUILDKIT=1 docker build \
		--progress=plain \
		--target controller \
		--build-arg BUILD_SUB_TARGET="-controller" \
		--build-arg PACKAGE=$(PACKAGE) \
		--build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg VCS_URL=$(VCS_URL) \
		-t $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) .

.PHONY: image-vaultenv
image-vaultenv:
	DOCKER_BUILDKIT=1 docker build \
		--progress=plain \
		--target vaultenv \
		--build-arg BUILD_SUB_TARGET="-vaultenv" \
		--build-arg PACKAGE=$(PACKAGE) \
		--build-arg VCS_REF=$(DOCKER_INTERNAL_TAG) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg VCS_URL=$(VCS_URL) \
		-t $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) .

.PHONY: image-akv2k8s-env-test
image-akv2k8s-env-test:
	DOCKER_BUILDKIT=1 docker build \
		--progress=plain \
		-t $(DOCKER_RELEASE_REG)/$(DOCKER_AKV2K8S_TEST_IMAGE) \
		-f images/akv2k8s-test/Dockerfile .

.PHONY: push
push: push-controller push-webhook push-vaultenv

.PHONY: push-controller
push-controller:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: push-webhook
push-webhook:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: push-vaultenv
push-vaultenv:
	docker push $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: push-akv2k8s-env-test
push-akv2k8s-env-test:
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_AKV2K8S_TEST_IMAGE)

.PHONY: pull-all
pull-all: pull-webhook pull-controller pull-vaultenv

.PHONY: pull-webhook
pull-webhook:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: pull-controller
pull-controller:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: pull-vaultenv
pull-vaultenv:
	docker pull $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG)

.PHONY: release
release: release-controller release-webhook release-vaultenv

.PHONY: release-controller
release-controller:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG_CONTROLLER)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):$(DOCKER_RELEASE_TAG_CONTROLLER)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_CONTROLLER_IMAGE):latest

.PHONY: release-webhook
release-webhook:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_RELEASE_TAG_WEBHOOK)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):$(DOCKER_RELEASE_TAG_WEBHOOK)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_WEBHOOK_IMAGE):latest

.PHONY: release-vaultenv
release-vaultenv:
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_RELEASE_TAG_VAULTENV)
	docker tag $(DOCKER_INTERNAL_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_INTERNAL_TAG) $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):latest

	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):$(DOCKER_RELEASE_TAG_VAULTENV)
	docker push $(DOCKER_RELEASE_REG)/$(DOCKER_VAULTENV_IMAGE):latest
