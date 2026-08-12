IMAGE_NAME ?= ghcr.io/absmach/atom
IMAGE_TAG ?= latest
ATOM_IMAGE ?= $(IMAGE_NAME):$(IMAGE_TAG)
ATOM_UI_IMAGE_NAME ?= ghcr.io/absmach/atom-ui
ATOM_UI_IMAGE_TAG ?= $(IMAGE_TAG)
ATOM_UI_IMAGE ?= $(ATOM_UI_IMAGE_NAME):$(ATOM_UI_IMAGE_TAG)
BUILD_TARGET ?= release
DOCKERFILE ?= Dockerfile
BUILD_CONTEXT ?= .
DOCKER_ATOM_DEV_IMAGE ?= $(ATOM_IMAGE)
DOCKER_ATOM_DEV_CONTEXT ?= target/docker_atom_dev
GIT_DESCRIBE := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_REVISION := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
ATOM_VERSION ?= $(GIT_DESCRIBE)
ATOM_REVISION ?= $(GIT_REVISION)
RELEASE_TAG ?= $(shell git describe --tags --exact-match --match 'v[0-9]*' HEAD 2>/dev/null)
DOCKER_BUILD_ARGS = --build-arg ATOM_VERSION="$(ATOM_VERSION)" --build-arg ATOM_REVISION="$(ATOM_REVISION)"
# Second tag applied alongside the primary one; `release` uses it to move
# `:latest` in the same build. Empty for every other target.
ATOM_IMAGE_EXTRA ?=
ATOM_UI_IMAGE_EXTRA ?=
ATOM_EXTRA_TAG = $(if $(ATOM_IMAGE_EXTRA),-t "$(ATOM_IMAGE_EXTRA)")
ATOM_UI_EXTRA_TAG = $(if $(ATOM_UI_IMAGE_EXTRA),-t "$(ATOM_UI_IMAGE_EXTRA)")
COMPOSE ?= docker compose
COMPOSE_PROFILES ?= --profile default --profile atom-ui
DEV_ENV_FILE ?= .env
COMPOSE_ENV = ATOM_IMAGE="$(ATOM_IMAGE)" ATOM_UI_IMAGE="$(ATOM_UI_IMAGE)"
# Ports for the host `make dev` flow. Kept distinct from the Compose ports
# (8080 / 3005) so `make up` and `make dev` can run at once on one Postgres.
DEV_HTTP_PORT ?= 8090
DEV_UI_PORT ?= 3000

.PHONY: help db dev build latest release release-check atom-build docker_atom_dev ui-build up down logs restart docker-build docker-build-release proto proto-lint proto-check

help:
	@echo "First run: create .env in the repo root — see README Quick Start"
	@echo ""
	@echo "Available targets:"
	@echo "  make build               Rebuild Atom backend + Atom UI images (run after code changes)"
	@echo "  make latest              Build both images as :latest with Git-derived build metadata"
	@echo "  make release             Build both images from a clean exact vX.Y.Z tag, also tagging :latest"
	@echo "  make atom-build          Rebuild only the Atom backend image"
	@echo "  make docker_atom_dev     Build Atom on the host, then copy the binary into a Docker image"
	@echo "  make ui-build            Rebuild only the Atom UI image"
	@echo "  make up                  Start Postgres, Atom, and Atom UI (builds images only if missing)"
	@echo "  make db                  Start only Postgres (for host 'cargo run')"
	@echo "  make dev                 Postgres (Docker) + host cargo run (:$(DEV_HTTP_PORT)) + host UI (:$(DEV_UI_PORT)); runs alongside 'make up'"
	@echo "  make restart             Restart the Compose stack (no rebuild; use 'make build' first)"
	@echo "  make proto               Regenerate protobuf outputs (gRPC reference docs + Rust bindings)"
	@echo "  make proto-lint          Lint the protos Atom owns"
	@echo "  make proto-check         Verify the vendored broker contract still matches upstream"
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
	@echo "  ATOM_VERSION=$(ATOM_VERSION)"
	@echo "  ATOM_REVISION=$(ATOM_REVISION)"
	@echo "  BUILD_TARGET=$(BUILD_TARGET)"
	@echo "  DOCKERFILE=$(DOCKERFILE)"
	@echo "  BUILD_CONTEXT=$(BUILD_CONTEXT)"
	@echo "  DOCKER_ATOM_DEV_IMAGE=$(DOCKER_ATOM_DEV_IMAGE)"
	@echo "  DOCKER_ATOM_DEV_CONTEXT=$(DOCKER_ATOM_DEV_CONTEXT)"

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

build: atom-build ui-build

latest:
	$(MAKE) build IMAGE_TAG=latest ATOM_VERSION="$(ATOM_VERSION)" ATOM_REVISION="$(ATOM_REVISION)"

# Also moves the local `:latest` tags, matching what the image workflow
# publishes on a tag push. Without it `make release && make up` would still
# run the previous build, since Compose defaults to `:latest`.
release: release-check
	$(MAKE) build IMAGE_TAG="$(RELEASE_TAG)" ATOM_VERSION="$(RELEASE_TAG)" ATOM_REVISION="$(ATOM_REVISION)" \
		ATOM_IMAGE_EXTRA="$(IMAGE_NAME):latest" ATOM_UI_IMAGE_EXTRA="$(ATOM_UI_IMAGE_NAME):latest"

release-check:
	@set -eu; \
	tag="$(RELEASE_TAG)"; \
	if [ -z "$$tag" ]; then \
		echo "release requires HEAD to have an exact vX.Y.Z Git tag" >&2; \
		exit 1; \
	fi; \
	if ! printf '%s\n' "$$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "release tag must use vX.Y.Z form, got $$tag" >&2; \
		exit 1; \
	fi; \
	if [ "$$(git rev-list -n 1 "$$tag")" != "$$(git rev-parse HEAD)" ]; then \
		echo "release tag $$tag does not point at HEAD" >&2; \
		exit 1; \
	fi; \
	if [ -n "$$(git status --porcelain --untracked-files=normal)" ]; then \
		echo "release requires a clean worktree, including no untracked files" >&2; \
		git status --short >&2; \
		exit 1; \
	fi

atom-build:
	docker build \
		-f $(DOCKERFILE) \
		--target $(BUILD_TARGET) \
		$(DOCKER_BUILD_ARGS) \
		-t "$(ATOM_IMAGE)" \
		$(ATOM_EXTRA_TAG) \
		$(BUILD_CONTEXT)

docker_atom_dev:
	@command -v cargo >/dev/null 2>&1 || { echo "cargo is required for 'make docker_atom_dev'"; exit 1; }
	@test -n "$(DOCKER_ATOM_DEV_CONTEXT)" || { echo "DOCKER_ATOM_DEV_CONTEXT must not be empty"; exit 1; }
	ATOM_BUILD_VERSION="$(ATOM_VERSION)" ATOM_BUILD_REVISION="$(ATOM_REVISION)" cargo build --release
	rm -rf -- "$(DOCKER_ATOM_DEV_CONTEXT)"
	mkdir -p "$(DOCKER_ATOM_DEV_CONTEXT)"
	install -m 0755 target/release/atom "$(DOCKER_ATOM_DEV_CONTEXT)/atom"
	cp -R migrations "$(DOCKER_ATOM_DEV_CONTEXT)/migrations"
	cp Dockerfile.atom-dev "$(DOCKER_ATOM_DEV_CONTEXT)/Dockerfile"
	docker build \
		$(DOCKER_BUILD_ARGS) \
		-t "$(DOCKER_ATOM_DEV_IMAGE)" \
		"$(DOCKER_ATOM_DEV_CONTEXT)"

ui-build:
	docker build \
		-f app/Dockerfile \
		$(DOCKER_BUILD_ARGS) \
		-t "$(ATOM_UI_IMAGE)" \
		$(ATOM_UI_EXTRA_TAG) \
		app

up:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) up -d postgres atom atom-ui

restart: down up

logs:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) logs -f atom atom-ui

down:
	$(COMPOSE_ENV) $(COMPOSE) --env-file $(DEV_ENV_FILE) $(COMPOSE_PROFILES) down $(args)

docker-build:
	docker build \
		-f $(DOCKERFILE) \
		--target $(BUILD_TARGET) \
		$(DOCKER_BUILD_ARGS) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		$(BUILD_CONTEXT)

docker-build-release:
	$(MAKE) docker-build BUILD_TARGET=release IMAGE_TAG=release

# ─── Protobuf ─────────────────────────────────────────────────────────────────
#
# Atom has two protobuf outputs, and only one of them is a file in the repo:
#
#   apidocs/grpc-reference.md  — checked in, produced by `buf generate`
#   the Rust service bindings  — NOT checked in; build.rs runs tonic-build on
#                                every compile and writes into cargo's OUT_DIR
#
# So this target regenerates the docs and then rebuilds, which is what refreshes
# the bindings. Editing a .proto and running `cargo build` is enough on its own —
# tonic-build emits `cargo:rerun-if-changed` for each proto — but the docs are
# generated by buf and will silently go stale without this.
proto:
	@command -v buf >/dev/null || { \
		echo "buf not found — install from https://buf.build/docs/installation"; exit 1; }
	@command -v protoc-gen-doc >/dev/null || { \
		echo "protoc-gen-doc not found — go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest"; exit 1; }
	buf generate
	cargo build

# The vendored broker contract is excluded in buf.yaml: Atom does not own its
# style, and editing it would break the byte-for-byte match `proto-check` needs.
proto-lint:
	buf lint

# Upstream owns proto/broker/v1/auth.proto. Nothing rebuilds it, so without this
# an upstream change surfaces at runtime. CI runs the same script.
proto-check:
	scripts/check-vendored-proto.sh
