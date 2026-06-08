IMAGE_NAME ?= ghcr.io/absmach/atom
IMAGE_TAG ?= latest
ATOM_IMAGE ?= $(IMAGE_NAME):$(IMAGE_TAG)
ATOM_DEV_IMAGE ?= $(IMAGE_NAME):dev
ATOM_UI_IMAGE_NAME ?= ghcr.io/absmach/atom-ui
ATOM_UI_IMAGE_TAG ?= $(IMAGE_TAG)
ATOM_UI_IMAGE ?= $(ATOM_UI_IMAGE_NAME):$(ATOM_UI_IMAGE_TAG)
BUILD_TARGET ?= release
DOCKERFILE ?= Dockerfile
BUILD_CONTEXT ?= .
COMPOSE ?= docker compose
COMPOSE_PROFILES ?= --profile default --profile atom-ui
DEV_ENV_FILE ?= .env.dev
COMPOSE_IMAGE_ENV = ATOM_IMAGE="$(ATOM_IMAGE)" ATOM_DEV_IMAGE="$(ATOM_DEV_IMAGE)" ATOM_UI_IMAGE="$(ATOM_UI_IMAGE)"

.PHONY: help dev-env build atom-build ui-build up down logs restart docker-build docker-build-release docker-build-dev

help:
	@echo "Available targets:"
	@echo "  make build               Build and tag Atom backend + Atom UI images for local dev"
	@echo "  make atom-build          Build and tag only the Atom backend image"
	@echo "  make ui-build            Build and tag only the Atom UI image"
	@echo "  make up                  Build and start Postgres, Atom, and Atom UI"
	@echo "  make restart             Rebuild and restart Postgres, Atom, and Atom UI"
	@echo "  make logs                Follow Atom + Atom UI logs"
	@echo "  make down                Stop the local Compose stack"
	@echo "  make dev-env             Create $(DEV_ENV_FILE) with local dev defaults"
	@echo "  make docker-build        Build the raw Atom Docker image for BUILD_TARGET"
	@echo "  make docker-build-release Build the raw release Docker image"
	@echo "  make docker-build-dev    Build the raw dev Docker image"
	@echo ""
	@echo "Variables:"
	@echo "  COMPOSE=$(COMPOSE)"
	@echo "  COMPOSE_PROFILES=$(COMPOSE_PROFILES)"
	@echo "  DEV_ENV_FILE=$(DEV_ENV_FILE)"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  ATOM_IMAGE=$(ATOM_IMAGE)"
	@echo "  ATOM_DEV_IMAGE=$(ATOM_DEV_IMAGE)"
	@echo "  ATOM_UI_IMAGE=$(ATOM_UI_IMAGE)"
	@echo "  BUILD_TARGET=$(BUILD_TARGET)"
	@echo "  DOCKERFILE=$(DOCKERFILE)"
	@echo "  BUILD_CONTEXT=$(BUILD_CONTEXT)"

dev-env:
	@if [ -f "$(DEV_ENV_FILE)" ]; then \
		echo "$(DEV_ENV_FILE) already exists"; \
	else \
		mkdir -p certs; \
		if [ ! -f certs/root-ca.crt ] || [ ! -f certs/root-ca.key ]; then \
			if ! command -v openssl >/dev/null 2>&1; then \
				echo "openssl is required to generate local dev CA files"; \
				exit 1; \
			fi; \
			openssl req -x509 -newkey rsa:2048 -nodes \
				-keyout certs/root-ca.key \
				-out certs/root-ca.crt \
				-days 3650 \
				-subj "/CN=Atom Dev Root CA" \
				-addext "basicConstraints=critical,CA:TRUE" \
				-addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1; \
		fi; \
		{ \
			echo "POSTGRES_USER=atom"; \
			echo "POSTGRES_PASSWORD=atom"; \
			echo "POSTGRES_DB=atom"; \
			echo "ADMIN_SECRET=12345678"; \
			echo "ATOM_MIN_PASSWORD_CHARS=8"; \
			echo "ATOM_SERVICE_SECRET=atom-dev-service-password"; \
			echo "ATOM_CERTS_ENABLED=true"; \
			echo "ATOM_CERTS_CA_MODE=file_root_issuer"; \
			echo "ATOM_CERTS_ROOT_CA_CERT_PATH=/certs/root-ca.crt"; \
			echo "ATOM_CERTS_ROOT_CA_KEY_PATH=/certs/root-ca.key"; \
			echo "ATOM_CERTS_CA_DIR=./certs"; \
			echo "ATOM_SIGNUP_ENABLED=false"; \
			echo "ATOM_HTTP_PORT=18080"; \
			echo "ATOM_PUBLIC_BASE_URL=http://localhost:18080"; \
			echo "ATOM_UI_HTTP_PORT=3005"; \
			echo "ATOM_GRAPHQL_URL=http://atom:8080/graphql"; \
		} > "$(DEV_ENV_FILE)"; \
		echo "Created $(DEV_ENV_FILE) with local developer defaults"; \
	fi

build: dev-env
	$(COMPOSE_IMAGE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) build atom atom-ui

atom-build: dev-env
	$(COMPOSE_IMAGE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) build atom

ui-build: dev-env
	$(COMPOSE_IMAGE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) build atom-ui

up: dev-env
	$(COMPOSE_IMAGE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) up -d --build postgres atom atom-ui

restart: down up

logs: dev-env
	$(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) logs -f atom atom-ui

down: dev-env
	$(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) down

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
