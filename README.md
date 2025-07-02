# Foxy 🦊

[![CI-Crate](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/crate.yml?label=crate-build)](https://github.com/johan-steffens/foxy/actions/workflows/crate.yml)
[![CI-Docker](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/docker.yml?label=docker-build)](https://github.com/johan-steffens/foxy/actions/workflows/docker.yml)
[![codecov](https://codecov.io/github/johan-steffens/foxy/graph/badge.svg?token=3L37Q54F17)](https://codecov.io/github/johan-steffens/foxy)
[![Crates.io Version](https://img.shields.io/crates/v/foxy-io)](https://crates.io/crates/foxy-io)
[![Crates.io Downloads](https://img.shields.io/crates/d/foxy-io)](https://crates.io/crates/foxy-io)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-blue)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)
[![Docker Version](https://img.shields.io/docker/v/johansteffens/foxy?label=docker%20tag)](https://hub.docker.com/r/johansteffens/foxy)
[![Docker Pulls](https://img.shields.io/docker/pulls/johansteffens/foxy)](https://hub.docker.com/r/johansteffens/foxy)
[![License](https://img.shields.io/github/license/johan-steffens/foxy)](https://github.com/johan-steffens/foxy/blob/main/LICENSE.md)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/johan-steffens/foxy)

A minimal, configuration-driven, hyper-extensible Rust HTTP proxy library.

## Use Cases

**Foxy is ideal for:**

- **API Gateway**: Centralize routing, security, and observability for your microservices.
- **Edge Proxy**: Secure and control traffic at the edge of your network.
- **Backend for Frontend (BFF)**: Tailor API responses for specific client applications.
- **Protocol Translation**: Transform requests and responses between different protocols.
- **Load Balancing**: Distribute incoming traffic across multiple upstream services.

## Features

- 🛣️ **Powerful Routing**: Predicate-based routing with path patterns, HTTP methods, headers, and query matching
- 🔄 **Flexible Filters**: Pre- and post-processing filters for request/response modification
- ⚙️ **Configuration Superpowers**: Layered configuration from files and environment variables
- 🌐 **Fine-grained Control**: Route-specific filter chains for precise request handling
- 🔒 **Pluggable Security**: Configurable authentication with built-in OIDC support
- 📊 **Observability**: OpenTelemetry integration for distributed tracing
- 📝 **Structured Logging**: JSON logging with trace IDs for better observability
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

### Building from Source

Foxy uses platform-specific TLS backends to optimize for different build environments and avoid dependency issues.

#### Prerequisites
- Rust 1.70+
- Platform-specific TLS dependencies handled automatically

#### Build
```bash
git clone https://github.com/johan-steffens/foxy.git
cd foxy
cargo build --release
```

#### TLS Backend Strategy
- **Windows**: Uses `rustls-tls` (pure Rust) to avoid OpenSSL build issues completely
- **Unix/Linux**: Uses `native-tls` with **vendored OpenSSL** for Docker builds
- **Docker**: Vendored SSL eliminates build-time dependency issues - no need to install OpenSSL at build time
- **Cross-compilation**: Platform detection ensures correct TLS backend automatically

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

For detailed configuration options, see the [Configuration Guide](docs/CONFIGURATION.md).

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
          "bypass": [
            { "methods": ["GET"], "path": "/health" }
          ]
        }
      }
    ]
  }
}
```

This configuration validates all requests against the identity provider, while allowing public access to `/health`.

### Structured Logging

Foxy supports structured JSON logging for better observability in production environments:
        
```json
{
  "proxy": {
    "logging": {
      "structured": true,
      "format": "json",
      "include_trace_id": true,
      "static_fields": {
        "environment": "production",
        "service": "api-gateway"
      }
    }
  }
}
```

Key benefits:
- **Trace IDs**: Every request gets a unique ID for end-to-end tracking
- **JSON Format**: Machine-parseable logs for integration with log aggregation systems
- **Rich Context**: Detailed request information and timing metrics
- **Static Fields**: Add environment-specific fields to all logs

For detailed configuration options, see the [Configuration Guide](docs/CONFIGURATION.md#structured-logging).

## Features

### OpenTelemetry Feature

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

### SwaggerUI Feature

Enable the Swagger UI feature:

```toml
# In your Cargo.toml
[dependencies]
foxy-io = { version = "...", features = ["swagger-ui"] }
```

Configure the OpenAPI schemas to be served on the Swagger UI in your configuration:

```json
{
  "proxy": {
    "swagger_ui": {
      "enabled": true,
      "path": "/swagger-ui",
      "sources": [
        {
          "name": "Petstore",
          "url": "https://petstore.swagger.io/v2/swagger.json"
        }
      ]
    }
  }
}
```

### Vault Config Feature

The `vault-config` feature enables secret interpolation from the filesystem into configuration values. This allows you to store sensitive information like passwords, API keys, and tokens in separate files and reference them in your configuration.

## Enabling the Feature

Add the `vault-config` feature to your `Cargo.toml`:

```toml
[dependencies]
foxy-io = { version = "0.3.6", features = ["vault-config"] }
```

Or enable it when building:

```bash
cargo build --features vault-config
```

### Usage

#### Basic Setup

1. Create a vault directory structure (default: `/vault/secret/`)
2. Store your secrets as individual files in the vault directory
3. Reference secrets in your configuration using `${secret.name}` syntax
4. Wrap your configuration provider with `VaultConfigProvider`

#### Example

**Vault directory structure:**
```
/vault/secret/
├── redis_password
```

**Secret files content:**
```bash
# /vault/secret/redis_password
super_secret_redis_password
```

**Configuration file (config.json):**
```json
{
  "server": {
    "listen": "0.0.0.0:8080",
    "redis_url": "redis://localhost:6379",
    "redis_password": "${secret.redis_password}"
  }
}
```

#### Example Application

See `examples/vault_example.rs` for a complete working example:

```bash
cargo run --example vault_example --features vault-config
```

This example demonstrates:
- Creating a temporary vault directory
- Setting up secret files
- Configuring the vault provider
- Accessing interpolated configuration values


## Extension Points

Foxy is designed to be highly extensible. You can inject your own custom logic into the proxy pipeline by implementing a few simple traits. This allows you to add custom routing rules, request/response modifications, and authentication mechanisms without forking the project.

The primary extension points are:
- **`Filter`**: Modify requests and responses.
- **`Predicate`**: Implement custom routing logic.
- **`SecurityProvider`**: Add custom authentication and authorization.

All extension points follow a similar pattern:
1.  **Implement** the corresponding trait.
2.  **Register** your implementation with Foxy's global registry at startup.
3.  **Use** your custom component in the configuration file.

For a detailed guide on adding extension points, see the [Extension Guide](docs/EXTENSION.md).

## License

This project is licensed under the [Mozilla Public License Version 2.0](LICENSE.md).

## Contributions

We welcome and appreciate contributions to Foxy! Please see our [Contribution Guide](docs/CONTRIBUTING.md) for details on how to get involved, including our development workflow, code style, and testing procedures.

### Contributors

A big thank you to all the individuals who have contributed to Foxy!

[Johan Steffens](https://github.com/johan-steffens)
[Armand Eicker](https://github.com/Armand-Eicker-Dev)
[Ohan Smit](https://github.com/Psynosaur)
