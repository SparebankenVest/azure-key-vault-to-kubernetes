build:
	docker build . -t dokken.azurecr.io/azure-keyvault-controller:0.0.1-tmp -f Dockerfile --build-arg PACKAGE=github.com/SparebankenVest/azure-key-vault-to-kubernetes --build-arg VCS_PROJECT_PATH="./cmd/azure-keyvault-controller" --build-arg VCS_REF=f3e10b2 --build-arg BUILD_DATE=2019-02-23T21:17:16Z --build-arg VCS_URL=https://github.com/SparebankenVest/azure-key-vault-to-kubernetes
