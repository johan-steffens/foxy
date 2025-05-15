# Foxy 🦊

[![CI-Crate](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/crate.yml?label=crate-build)](https://github.com/johan-steffens/foxy/actions/workflows/crate.yml)
[![CI-Docker](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/docker.yml?label=docker-build)](https://github.com/johan-steffens/foxy/actions/workflows/docker.yml)
[![Crates.io Version](https://img.shields.io/crates/v/foxy-io)](https://crates.io/crates/foxy-io)
[![Crates.io Downloads](https://img.shields.io/crates/d/foxy-io)](https://crates.io/crates/foxy-io)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-blue)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)
[![Docker Version](https://img.shields.io/docker/v/johansteffens/foxy?label=docker%20tag)](https://hub.docker.com/r/johansteffens/foxy)
[![Docker Pulls](https://img.shields.io/docker/pulls/johansteffens/foxy)](https://hub.docker.com/r/johansteffens/foxy)
[![License](https://img.shields.io/github/license/johan-steffens/foxy)](https://github.com/johan-steffens/foxy/blob/main/LICENSE.md)

A minimal, configuration-driven, hyper-extensible Rust HTTP proxy library.

## Features

- 🛣️ **Powerful Routing**: Predicate-based routing with path patterns, HTTP methods, headers, and query matching
- 🔄 **Flexible Filters**: Pre- and post-processing filters for request/response modification
- ⚙️ **Configuration Superpowers**: Layered configuration from files and environment variables
- 🌐 **Fine-grained Control**: Route-specific filter chains for precise request handling
- 🔒 **Pluggable Security**: Configurable authentication with built-in OIDC support
- 📊 **Observability**: OpenTelemetry integration for distributed tracing
- 🚀 **Modern Async Architecture**: Built on Tokio and Hyper for high performance
- 📦 **Lightweight Dependencies**: Minimal external dependencies for core functionality
- 🧩 **Highly Extensible**: Custom predicates, filters, and security providers via simple traits
- 🚢 **Docker Support**: Official container image for rapid deployment

## Quickstart

### As a Library

Add Foxy to your `Cargo.toml`:

```toml
[dependencies]
foxy-io = "..."
```

Build an instance and start the server:

```rust
use foxy::Foxy;

// Create a new Foxy instance with layered configuration
let foxy = Foxy::loader()
    .with_env_vars()                  // Environment variables (highest priority)
    .with_config_file("config.toml")  // File-based config (medium priority)
    .with_config_file("defaults.toml") // Defaults (lowest priority)
    .build().await?;

// Start the proxy server and wait for it to complete
foxy.start().await?;
```

### Run the Example

```bash
git clone https://github.com/johan-steffens/foxy.git
cd foxy
export RUST_LOG=debug
export FOXY_CONFIG_FILE=$(pwd)/config/example.json
cargo run --bin foxy
```

### Run with Docker

> **Prerequisites:** Docker 20.10+ installed  

Pull the multi-arch image:

```bash
docker pull johansteffens/foxy:latest
```

Run the proxy, exposing port **8080**:

```bash
docker run --rm -p 8080:8080 johansteffens/foxy:latest
```

#### Using a Custom Configuration

1. Create a `config.json` file on your host
2. Ensure your configuration binds to address `0.0.0.0`
3. Mount it into the container:

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/config.json:/app/config.json:ro" \
  -e FOXY_CONFIG_FILE=/app/config.json \
  johansteffens/foxy:latest 
```

### Run with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: "3.9"
services:
  foxy:
    image: johansteffens/foxy:latest
    container_name: foxy
    ports:
      - "8080:8080"
    environment:
      FOXY_CONFIG_FILE: /config/config.json
    volumes:
      - ./config.json:/config/config.json:ro
```

Start the service:

```bash
docker compose up -d
```

> **Tip:** When you update `config.json`, restart with `docker compose restart foxy` to apply changes.

## Core Concepts

### Routing System

Foxy uses a predicate-based routing system to determine how requests are handled:

- **Predicates**: Conditions that match against request properties (path, method, headers, query)
- **Priority**: Routes with higher priority are evaluated first
- **Filters**: Processing steps applied to matched routes

### Configuration

Foxy's configuration can be provided through multiple sources:

```rust
// Build a layered configuration
let foxy = Foxy::loader()
    .with_env_vars()                   // First priority
    .with_config_file("config.json")   // Second priority
    .build().await?;
```

Example configuration:

```json
{
  "routes": [
    {
      "id": "api-route",
      "target": "https://api.example.com",
      "filters": [
        {
          "type": "path_rewrite",
          "config": {
            "pattern": "^/api/(.*)$",
            "replacement": "/v2/$1"
          }
        }
      ],
      "predicates": [
        {
          "type_": "path",
          "config": {
            "pattern": "/api/*"
          }
        }
      ]
    }
  ]
}
```

For detailed configuration options, see the [Configuration Guide](./CONFIGURATION.md).

### Security

Add JWT validation with the OIDC security provider:

```json
{
  "proxy": {
    "security_chain": [
      {
        "type": "oidc",
        "config": {
          "issuer-uri": "https://id.example.com/.well-known/openid-configuration",
          "aud": "my-api",
          "bypass-routes": [
            { "methods": ["GET"], "path": "/health" }
          ]
        }
      }
    ]
  }
}
```

This configuration validates all requests against the identity provider, while allowing public access to `/health`.

### OpenTelemetry Integration

Enable distributed tracing with OpenTelemetry:

```toml
# In your Cargo.toml
[dependencies]
foxy-io = { version = "...", features = ["opentelemetry"] }
```

Configure the OpenTelemetry collector in your configuration:

```json
{
  "proxy": {
    "opentelemetry": {
      "endpoint": "http://otel-collector:4317",
      "service_name": "my-proxy-service",
      "include_headers": true,
      "resource_attributes": {
        "host.name": "proxy-pod-abc123"
      },
      "collector_headers": {
        "X-API-Key": "d41000b6-6191-47c5-99f1-7b88b1b97409"
      }
    }
  }
}
```


## Performance Features

### Streaming Architecture

- **Zero-Copy Streaming**: Request and response bodies are streamed end-to-end
- **Backpressure Support**: Large uploads/downloads propagate backpressure correctly
- **Memory Efficiency**: Memory usage is bound by socket buffers, not by request/response size

### Detailed Metrics

Foxy logs three high-resolution latencies on every call (DEBUG level):

```
[timing] GET /api/users -> 200 | total=152ms upstream=148ms internal=4ms
```

| Metric | Description |
|--------|-------------|
| **total** | Wall-clock time from first byte in to last byte out |
| **upstream** | Time spent awaiting the target server |
| **internal** | Proxy-side processing time (`total − upstream`) |

### Request and Response Logging

The `LoggingFilter` can peek and log request/response bodies:

- Logs the first 1,000 bytes/characters (UTF-8 lossy conversion)
- Safely handles binary or large payloads
- Configurable log level and content limits

> **Note:** Body logging adds some latency to proxied calls.

## Extension Points

Foxy is designed to be extended through traits:

- **ConfigProvider**: Add custom configuration sources
- **Filter**: Create custom request/response processing logic
- **Predicate**: Implement custom routing logic
- **SecurityProvider**: Add authentication mechanisms

## Development Status

- [x] Configuration System
- [x] Loader Module
- [x] Core HTTP Proxy
- [x] Predicate-based Routing
- [x] Request/Response Filters
- [x] Security Chain
  - [x] OIDC provider
  - [ ] Basic auth provider
- [x] OpenTelemetry Integration

## License

This project is licensed under the [Mozilla Public License Version 2.0](LICENSE.md).
