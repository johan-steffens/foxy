# syntax=docker/dockerfile:1.6
# --- Build stage ---
FROM --platform=$TARGETPLATFORM rust:1.86.0-alpine3.21 AS builder
ARG TARGETPLATFORM

#—Install compiler toolchain and common build deps
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        build-base musl-dev pkgconf git \
        openssl-dev openssl-libs-static   \
        perl perl-utils

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
RUN cargo fetch

COPY . .

ENV OPENSSL_STATIC=1
ENV OPENSSL_NO_VENDOR=1

RUN set -eux; \
    case "$TARGETPLATFORM" in \
        "linux/amd64")   RUST_TARGET=x86_64-unknown-linux-musl   ;; \
        "linux/arm64")   RUST_TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "Unsupported platform $TARGETPLATFORM" && exit 1 ;; \
    esac; \
    rustup target add $RUST_TARGET; \
    cargo build --release --bin foxy \
        --target $RUST_TARGET --target-dir /cargo_target; \
    strip /cargo_target/$RUST_TARGET/release/foxy; \
    mkdir -p /out && cp /cargo_target/$RUST_TARGET/release/foxy /out/

# --- Runtime stage ---
FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /out/foxy /usr/local/bin/foxy

EXPOSE 8080
ENTRYPOINT ["foxy"]