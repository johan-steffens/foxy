# -------- Build stage -------------------------------------------------
FROM rust:1.86.0-alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig build-base
ENV OPENSSL_STATIC=1

COPY . .
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --bin foxy --target x86_64-unknown-linux-musl
RUN pwd
RUN ls -la

# -------- Runtime stage ----------------------------------------------
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/johan-steffens/foxy"

COPY --from=builder target/x86_64-unknown-linux-musl/release/foxy /foxy
# Conventional config location
COPY config/default.toml /etc/foxy/config.toml

EXPOSE 8080
ENTRYPOINT ["/foxy"]