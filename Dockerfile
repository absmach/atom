ARG ATOM_VERSION=dev
ARG ATOM_REVISION=unknown

FROM rust:1.89-alpine AS base
RUN apk add --no-cache build-base cmake musl-dev openssl-dev perl pkgconfig protobuf-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs

FROM base AS deps-release
RUN cargo build --release && rm -rf src

FROM base AS deps-dev
RUN cargo build && rm -rf src

FROM deps-release AS builder-release
ARG ATOM_VERSION
ARG ATOM_REVISION
ENV ATOM_BUILD_VERSION=${ATOM_VERSION}
ENV ATOM_BUILD_REVISION=${ATOM_REVISION}
COPY . .
RUN touch src/main.rs && cargo build --release

FROM deps-dev AS builder-dev
ARG ATOM_VERSION
ARG ATOM_REVISION
ENV ATOM_BUILD_VERSION=${ATOM_VERSION}
ENV ATOM_BUILD_REVISION=${ATOM_REVISION}
COPY . .
RUN touch src/main.rs && cargo build

FROM alpine:3.24 AS release
ARG ATOM_VERSION
ARG ATOM_REVISION
LABEL org.opencontainers.image.title="Atom" \
    org.opencontainers.image.version="${ATOM_VERSION}" \
    org.opencontainers.image.revision="${ATOM_REVISION}"
# No runtime ENV for these: the binary has them compiled in via build.rs, so an
# env var here could disagree with what the process actually reports.
RUN apk add --no-cache ca-certificates libgcc \
    && addgroup -S atom \
    && adduser -S -G atom atom
WORKDIR /app
COPY --from=builder-release /app/target/release/atom /usr/local/bin/atom
COPY migrations ./migrations
COPY email-templates ./email-templates
RUN chown -R atom:atom /app /usr/local/bin/atom
USER atom
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health/ready || exit 1
CMD ["atom"]

FROM alpine:3.24 AS dev
ARG ATOM_VERSION
ARG ATOM_REVISION
LABEL org.opencontainers.image.title="Atom" \
    org.opencontainers.image.version="${ATOM_VERSION}" \
    org.opencontainers.image.revision="${ATOM_REVISION}"
# No runtime ENV for these: the binary has them compiled in via build.rs, so an
# env var here could disagree with what the process actually reports.
RUN apk add --no-cache ca-certificates libgcc \
    && addgroup -S atom \
    && adduser -S -G atom atom
WORKDIR /app
COPY --from=builder-dev /app/target/debug/atom /usr/local/bin/atom
COPY migrations ./migrations
COPY email-templates ./email-templates
RUN chown -R atom:atom /app /usr/local/bin/atom
USER atom
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health/ready || exit 1
CMD ["atom"]
