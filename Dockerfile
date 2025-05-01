# syntax=docker/dockerfile:1.6
# --- Build stage ---
FROM --platform=$BUILDPLATFORM rust:1.86.0-alpine AS builder
ARG TARGETPLATFORM

#—Install compiler toolchain and common build deps
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache build-base musl-dev openssl-dev pkgconf git

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
RUN cargo fetch

COPY . .

RUN set -eux; \
    case "$TARGETPLATFORM" in \
        "linux/amd64")  RUST_TARGET=x86_64-unknown-linux-musl ;; \
        "linux/arm64")  RUST_TARGET=aarch64-unknown-linux-musl ;; \
        "linux/arm/v7") RUST_TARGET=armv7-unknown-linux-musleabihf ;; \
        *) echo "Unsupported platform $TARGETPLATFORM" && exit 1 ;; \
    esac; \
    rustup target add $RUST_TARGET; \
    cargo build --release --bin foxy --target $RUST_TARGET --target-dir /cargo_target; \
    strip /cargo_target/$RUST_TARGET/release/foxy; \
    mkdir -p /out; \
    cp /cargo_target/$RUST_TARGET/release/foxy /out/

# --- Runtime stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates
COPY --from=builder /out/foxy /usr/local/bin/foxy

EXPOSE 8080
ENTRYPOINT ["foxy"]