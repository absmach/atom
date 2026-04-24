FROM rust:1.88-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev protobuf-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY . .
RUN touch src/main.rs && cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates libgcc
COPY --from=builder /app/target/release/atom /usr/local/bin/atom
EXPOSE 8080
CMD ["atom"]
