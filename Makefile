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
# Ports for the host `make dev` flow. Kept distinct from the Compose ports
# (8080 / 3005) so `make up` and `make dev` can run at once on one Postgres.
DEV_HTTP_PORT ?= 8090
DEV_UI_PORT ?= 3000

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
	@echo "  make dev                 Postgres (Docker) + host cargo run (:$(DEV_HTTP_PORT)) + host UI (:$(DEV_UI_PORT)); runs alongside 'make up'"
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
	@echo "  DEV_HTTP_PORT=$(DEV_HTTP_PORT)"
	@echo "  DEV_UI_PORT=$(DEV_UI_PORT)"
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
# Backend on :$(DEV_HTTP_PORT), UI on :$(DEV_UI_PORT), sharing the Compose
# Postgres. Distinct from `make up` (8080 / 3005), so both can run at once.
# Ctrl-C stops both host processes.
dev: db
	@command -v cargo >/dev/null 2>&1 || { echo "cargo is required for 'make dev'"; exit 1; }
	@command -v pnpm  >/dev/null 2>&1 || { echo "pnpm is required for 'make dev'"; exit 1; }
	@trap 'kill 0' INT TERM EXIT; \
	LISTEN_ADDR=0.0.0.0:$(DEV_HTTP_PORT) ATOM_PUBLIC_BASE_URL=http://localhost:$(DEV_HTTP_PORT) cargo run & \
	( cd app && pnpm install --frozen-lockfile && \
	  ATOM_GRAPHQL_URL=http://localhost:$(DEV_HTTP_PORT)/graphql PORT=$(DEV_UI_PORT) pnpm dev ) & \
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
