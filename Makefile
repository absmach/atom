IMAGE_NAME ?= ghcr.io/absmach/atom
IMAGE_TAG ?= latest
ATOM_IMAGE ?= $(IMAGE_NAME):$(IMAGE_TAG)
ATOM_UI_IMAGE_NAME ?= ghcr.io/absmach/atom-ui
ATOM_UI_IMAGE_TAG ?= $(IMAGE_TAG)
ATOM_UI_IMAGE ?= $(ATOM_UI_IMAGE_NAME):$(ATOM_UI_IMAGE_TAG)
BUILD_TARGET ?= release
DOCKERFILE ?= Dockerfile
BUILD_CONTEXT ?= .
COMPOSE ?= docker compose
COMPOSE_PROFILES ?= --profile default --profile atom-ui
DEV_ENV_FILE ?= .env
COMPOSE_ENV = ATOM_IMAGE="$(ATOM_IMAGE)" ATOM_UI_IMAGE="$(ATOM_UI_IMAGE)"

.PHONY: help db dev build atom-build ui-build up down logs restart docker-build docker-build-release

help:
	@echo "First run: cp .env.example .env"
	@echo ""
	@echo "Available targets:"
	@echo "  make build               Build and tag Atom backend + Atom UI images for local dev"
	@echo "  make atom-build          Build and tag only the Atom backend image"
	@echo "  make ui-build            Build and tag only the Atom UI image"
	@echo "  make up                  Build and start Postgres, Atom, and Atom UI"
	@echo "  make db                  Start only Postgres (for host 'cargo run')"
	@echo "  make dev                 Postgres (Docker) + host cargo run + host UI dev server"
	@echo "  make restart             Rebuild and restart Postgres, Atom, and Atom UI"
	@echo "  make logs                Follow Atom + Atom UI logs"
	@echo "  make down                Stop the local Compose stack"
	@echo "  make docker-build        Build the raw Atom Docker image for BUILD_TARGET"
	@echo "  make docker-build-release Build the raw release Docker image"
	@echo ""
	@echo "Variables:"
	@echo "  COMPOSE=$(COMPOSE)"
	@echo "  COMPOSE_PROFILES=$(COMPOSE_PROFILES)"
	@echo "  DEV_ENV_FILE=$(DEV_ENV_FILE)"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  ATOM_IMAGE=$(ATOM_IMAGE)"
	@echo "  ATOM_UI_IMAGE=$(ATOM_UI_IMAGE)"
	@echo "  BUILD_TARGET=$(BUILD_TARGET)"
	@echo "  DOCKERFILE=$(DOCKERFILE)"
	@echo "  BUILD_CONTEXT=$(BUILD_CONTEXT)"

db:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) up -d postgres

# Full host dev loop: Postgres in Docker, Atom and the Next UI on the host.
# Backend on :8080, UI on :3000. Ctrl-C stops both. Do not run alongside `make up`.
dev: db
	@command -v cargo >/dev/null 2>&1 || { echo "cargo is required for 'make dev'"; exit 1; }
	@command -v pnpm  >/dev/null 2>&1 || { echo "pnpm is required for 'make dev'"; exit 1; }
	@trap 'kill 0' INT TERM EXIT; \
	cargo run & \
	( cd app && pnpm install --frozen-lockfile && pnpm dev ) & \
	wait

build:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) build atom atom-ui

atom-build:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) build atom

ui-build:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) build atom-ui

up:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) up -d --build postgres atom atom-ui

restart: down up

logs:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) logs -f atom atom-ui

down:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) down

docker-build:
	docker build \
		-f $(DOCKERFILE) \
		--target $(BUILD_TARGET) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		$(BUILD_CONTEXT)

docker-build-release:
	$(MAKE) docker-build BUILD_TARGET=release IMAGE_TAG=release
