# -------- Build stage -------------------------------------------------
FROM rust:1.86.0-alpine AS builder
RUN apk add --no-cache musl-dev gcc openssl-dev openssl-libs-static pkgconfig build-base \
    && rustup target add x86_64-unknown-linux-musl
ENV OPENSSL_STATIC=1

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    cargo build --release --bin foxy --target x86_64-unknown-linux-musl

# -------- Runtime stage ----------------------------------------------
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/johan-steffens/foxy"

COPY --from=builder target/x86_64-unknown-linux-musl/release/foxy /foxy
# Conventional config location
COPY config/default.toml /etc/foxy/config.toml

EXPOSE 8080
ENTRYPOINT ["/foxy"]