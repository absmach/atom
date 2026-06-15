FROM rust:1.89-alpine AS base
RUN apk add --no-cache build-base cmake musl-dev openssl-dev perl pkgconfig protobuf-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs

FROM base AS deps-release
RUN cargo build --release && rm -rf src

FROM deps-release AS builder-release
COPY . .
RUN touch src/main.rs && cargo build --release

FROM alpine:3.20 AS release
RUN apk add --no-cache ca-certificates libgcc
WORKDIR /app
COPY --from=builder-release /app/target/release/atom /usr/local/bin/atom
COPY migrations ./migrations
EXPOSE 8080
CMD ["atom"]
