# Foxy 🦊

[![CI-Crate](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/crate.yml?label=crate-build)](https://github.com/johan-steffens/foxy/actions/workflows/crate.yml)
[![CI-Docker](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/docker.yml?label=docker-build)](https://github.com/johan-steffens/foxy/actions/workflows/crate.yml)
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
- 🔒 **Pluggable Security Chain**: configurable, provider-based request authentication with built-in providers
- 🚀 **Modern Async Architecture**: Built on Tokio and Hyper for high performance
- 📦 **Lightweight Dependencies**: Minimal external dependencies for core functionality
- 🧩 **Highly Extensible**: Custom predicates, filters *and* security providers via simple traits
- 🚢 **Docker Support**: Official container image for rapid deployment

## Quickstart

### Run the basic proxy example

```bash
git clone https://github.com/johan-steffens/foxy.git
cd foxy
cargo run --example basic-proxy
```

### Run it in your code

Add Foxy as a dependency to your `Cargo.toml` file

```toml
[dependencies]
foxy-io = "..."
```

Build an instance and start the server.

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

### Run with Docker

> **Prerequisites:** Docker 20.10+ installed  

The project publishes multi‑arch images to GitHub Container Registry:

```bash
docker pull johansteffens/foxy:latest
```

Run the proxy, exposing the default port **8080** on your host:

```bash
docker run --rm -p 8080:8080 johansteffens/foxy:latest
```

#### Passing a custom configuration file

1. Create (or copy) a `config.*` file on your host.
2. Ensure your configuration binds to address `0.0.0.0`
3. Mount it into the container and tell Foxy where to find it with the `FOXY_CONFIG_FILE` environment variable:

```bash
docker run --rm -p 8080:8080 -v "$(pwd)/config.json:/app/config.json:ro" -e FOXY_CONFIG_FILE=/app/config.json johansteffens/foxy:latest 
```

### Run with docker‑compose

If you prefer **docker‑compose**, drop the snippet below into `docker-compose.yml` and run `docker compose up -d`:

```yaml
version: "3.9"
services:
  foxy:
    image: johansteffens/foxy:latest
    container_name: foxy
    ports:
      - "8080:8080"
    environment:
      # Tell Foxy to load the configuration we mounted
      FOXY_CONFIG_FILE: /config/config.json
    volumes:
      # Mount your custom configuration
      - ./config.json:/config/config.json:ro
```

> **Tip:** When you update `config.json`, simply restart the container with  
> `docker-compose restart foxy` to pick up the changes.

## Core Principles
- **Predictable Routing**: Predicate-based matching with clear priorities determines how requests are routed  
- **Configurable Processing**: Route-specific and global filters for request/response modification  
- **Extensibility**: Trait-based design enables custom predicates and filters  
- **Configuration-Driven**: All behavior controlled via flexible configuration with sensible defaults  

## Configuration
Foxy's power comes from its rich configuration system. Here's a brief overview:

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

For detailed information on all configuration options, see the [Configuration Guide](./CONFIGURATION.md).

### Configuration Sources

Foxy supports multiple configuration sources with priority order:

```rust
// Build a layered configuration
let foxy = Foxy::loader()
    .with_env_vars()                   // First priority
    .with_config_file("config.json")   // Second priority
    .build().await?;
```

Example: `FOXY_SERVER_PORT=8080` → `server.port`

### Enabling security

Add a `security_chain` with a configured provider to your proxy configuration:

```jsonc
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

That’s it — requests hitting `/api/**` will be validated against the IDP while `/health` remains public.
Full configuration examples can be found in the [Configuration Guide](CONFIGURATION.md).

## Streaming bodies

* Foxy proxies **request and response bodies as streams** end‑to‑end to ensure there's no full body buffering in memory.  
* Large uploads/downloads back‑pressure correctly.  
* Memory usage is bound only by socket buffers.  

### Detailed timing metrics

* Foxy records and logs three high‑resolution latencies on every call (DEBUG level):

`[timing] <METHOD> <PATH> -> <STATUS> | total=<X> upstream=<Y> internal=<Z>`

| field      | description                                                    |
|------------|----------------------------------------------------------------|
| **total**  | wall‑clock time from first byte in to last byte out            |
| **upstream** | time spent awaiting the target server                        |
| **internal** | proxy‑side routing / filtering / logging (`total − upstream`)|

### Request and Response body logging

* `LoggingFilter` peeks and logs the first 1 000 bytes/characters of every request and response body (UTF‑8‑lossy).  
* Binary or very large payloads are safe—the remainder of the stream is forwarded untouched.  
* **Please note:** enabling request and response logging will introduce additional latency to your calls.

## Development Status

- [x] Configuration System
- [x] Loader Module
- [x] Core HTTP Proxy
- [x] Predicate-based Routing
- [x] Request/Response Filters
- [x] Security Chain
  - [x] OIDC provider
  - [ ] Basic auth provider

## License
This project is licensed under [Mozilla Public License Version 2.0](LICENSE.md)