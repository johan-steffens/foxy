# syntax=docker/dockerfile:1.6
# --- Build stage ---
FROM --platform=$BUILDPLATFORM rust:1.86.0-alpine AS builder
ARG TARGETPLATFORM

#—Install compiler toolchain and common build deps
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        build-base \
        musl-dev \
        perl perl-utils \
        pkgconf git && \
    # ── OPENSSL EXPECTS canonical *-linux-musl-gcc ──
    case "$TARGETPLATFORM" in \
        "linux/arm64") \
            ln -sf /usr/bin/cc /usr/local/bin/aarch64-linux-musl-gcc ;; \
        "linux/arm/v7") \
            ln -sf /usr/bin/cc /usr/local/bin/armv7-linux-musleabihf-gcc ;; \
    esac

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
RUN cargo fetch

COPY . .

ENV OPENSSL_STATIC=1

RUN set -eux; \
    case "$TARGETPLATFORM" in \
        "linux/amd64")  RUST_TARGET=x86_64-unknown-linux-musl OPENSSL_TARGET=linux-x86_64 ;; \
        "linux/arm64")  RUST_TARGET=aarch64-unknown-linux-musl OPENSSL_TARGET=linux-aarch64 ;; \
        "linux/arm/v7") RUST_TARGET=armv7-unknown-linux-musleabihf OPENSSL_TARGET=linux-armv4 ;; \
        *) echo "Unsupported platform $TARGETPLATFORM" && exit 1 ;; \
    esac; \
    rustup target add $RUST_TARGET; \
    export OPENSSL_CONFIGURE="$OPENSSL_TARGET no-asm"; \
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