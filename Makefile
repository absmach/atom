IMAGE_NAME ?= ghcr.io/absmach/atom
IMAGE_TAG ?= latest
BUILD_TARGET ?= release
DOCKERFILE ?= Dockerfile
BUILD_CONTEXT ?= .

.PHONY: help docker-build docker-build-release docker-build-dev build

help:
	@echo "Available targets:"
	@echo "  make docker-build        Build the Atom Docker image for BUILD_TARGET"
	@echo "  make docker-build-release Build the release Docker image"
	@echo "  make docker-build-dev    Build the dev Docker image"
	@echo "  make build               Alias for docker-build"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  BUILD_TARGET=$(BUILD_TARGET)"
	@echo "  DOCKERFILE=$(DOCKERFILE)"
	@echo "  BUILD_CONTEXT=$(BUILD_CONTEXT)"

docker-build:
	docker build \
		-f $(DOCKERFILE) \
		--target $(BUILD_TARGET) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		$(BUILD_CONTEXT)

docker-build-release:
	$(MAKE) docker-build BUILD_TARGET=release IMAGE_TAG=release

docker-build-dev:
	$(MAKE) docker-build BUILD_TARGET=dev IMAGE_TAG=dev

build: docker-build
