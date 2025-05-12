# syntax=docker/dockerfile:1.6
# --- Build stage ---
# (1) Add zigbuild & Cargo targets
FROM --platform=$BUILDPLATFORM rust:alpine3.21 AS chef

WORKDIR /app

 # vendored OpenSSL: no system openssl-dev, but we need perl & make
ENV PKG_CONFIG_ALLOW_CROSS=1 \
    PKGCONFIG_SYSROOTDIR=/ \
    OPENSSL_STATIC=1
RUN apk add --no-cache musl-dev zig perl make pkgconf protobuf-dev
RUN cargo install --locked cargo-zigbuild cargo-chef
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# (2) plan the build using chef
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# (3) building project dependencies
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json --release --zigbuild \
  --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

# (4) build for current architecture
COPY . .
RUN cargo zigbuild --features opentelemetry -r --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
  && mkdir /app/linux \
  && cp target/aarch64-unknown-linux-musl/release/foxy /app/foxy-arm64 \
  && cp target/x86_64-unknown-linux-musl/release/foxy /app/foxy-amd64

# --- Runtime stage ---
FROM alpine:3.21
ARG TARGETARCH
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/foxy-${TARGETARCH} /foxy
CMD "/foxy"