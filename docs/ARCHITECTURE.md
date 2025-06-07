# Foxy Architecture Overview

## Introduction

Foxy is an HTTP proxy library designed with a focus on architectural extensibility and configuration-driven behavior. At its core, Foxy implements a request/response pipeline architecture that processes HTTP traffic through a series of well-defined stages. This document describes the internal structure of Foxy, the relationships between its components, and the design principles that guide its implementation.

## Problem Statement

API gateways in modern architectures need to balance performance with flexibility. Foxy addresses this challenge through:

- A minimal core that handles the essential proxy functionality
- A trait-based extension system for custom behavior
- A configuration-first approach that minimizes code changes
- A streaming architecture that efficiently handles large payloads

## Core Architectural Components

Foxy's architecture is built around several key subsystems:

- **Request Pipeline**: A sequential processing chain for HTTP requests and responses
- **Routing Engine**: A predicate evaluation system that determines request destinations
- **Configuration System**: A layered approach to settings with provider abstraction
- **Filter Framework**: Pre/post processing hooks for request/response modification
- **Security Layer**: Pluggable authentication and authorization mechanisms
- **Observability Stack**: Integrated logging, metrics, and distributed tracing

## Project Structure

```
foxy/
├── src/
│   ├── bin/
│   │   └── foxy.rs                 # Binary entrypoint
│   ├── config/                     # Configuration subsystem
│   │   ├── env.rs                  # Environment variable config provider
│   │   ├── error.rs                # Configuration errors
│   │   ├── file.rs                 # File-based config provider
│   │   ├── mod.rs                  # Config module entry point
│   │   └── tests.rs                # Config tests
│   ├── core/                       # Core proxy primitives
│   │   ├── mod.rs                  # Request/response types, ProxyCore
│   │   └── tests.rs                # Core tests
│   ├── filters/                    # Request/response filters
│   │   ├── mod.rs                  # Filter implementations
│   │   └── tests.rs                # Filter tests
│   ├── loader/                     # High-level initialization
│   │   ├── mod.rs                  # FoxyLoader implementation
│   │   └── tests.rs                # Loader tests
│   ├── logging/                    # Logging utilities
│   │   └── mod.rs                  # Logging implementation
│   ├── opentelemetry/              # Tracing integration
│   │   └── mod.rs                  # OpenTelemetry implementation
│   ├── router/                     # Request routing
│   │   ├── mod.rs                  # Router implementation
│   │   ├── predicates.rs           # Predicate implementations
│   │   └── tests.rs                # Router tests
│   ├── security/                   # Authentication & authorization
│   │   ├── mod.rs                  # Security chain implementation
│   │   ├── oidc.rs                 # OIDC provider implementation
│   │   └── tests.rs                # Security tests
│   ├── server/                     # HTTP server implementation
│   │   ├── health.rs               # Health check endpoints
│   │   ├── mod.rs                  # Server implementation
│   │   └── tests.rs                # Server tests
│   └── lib.rs                      # Library entry point and re-exports
├── Cargo.toml                      # Project manifest
├── Dockerfile                      # Multi-arch container build
└── README.md                       # Project documentation
```

## Architecture Components

### 1. Core Components

#### ProxyCore

The `ProxyCore` is the central component that processes HTTP requests through the proxy pipeline. It:

- Manages the HTTP client for outbound requests
- Applies security providers for authentication
- Executes pre-filters on incoming requests
- Routes requests to appropriate targets
- Applies post-filters on responses
- Collects timing metrics for observability

#### Request/Response Model

- `ProxyRequest`: Represents an HTTP request with method, path, headers, and streaming body
- `ProxyResponse`: Represents an HTTP response with status, headers, and streaming body
- `RequestContext`/`ResponseContext`: Contextual data that can be accessed and modified by filters

### 2. Configuration System

Foxy uses a layered configuration approach that allows settings to be loaded from multiple sources:

- **Environment Variables**: Highest priority, prefixed with `FOXY_` by default
- **Configuration Files**: Support for JSON, TOML, and YAML (with feature flag)
- **Default Values**: Fallback values for optional settings

The configuration system is extensible through the `ConfigProvider` trait, allowing custom sources to be implemented.

### 3. Routing System

The routing system determines how requests are matched to backend services:

- **PredicateRouter**: Matches requests against a set of predicates
- **Predicates**: Conditions that match against request properties:
  - `PathPredicate`: Matches URL paths using glob patterns
  - `MethodPredicate`: Matches HTTP methods
  - `HeaderPredicate`: Matches request headers
  - `QueryPredicate`: Matches query parameters

Routes are evaluated in priority order, with the first matching route being selected.

### 4. Filter System

Filters process requests and responses at different stages of the proxy pipeline:

- **Pre-filters**: Applied before the request is sent to the target
- **Post-filters**: Applied after the response is received from the target
- **Both**: Applied at both stages

Built-in filters include:
- `LoggingFilter`: Logs request/response details
- `HeaderFilter`: Adds, removes, or modifies headers
- `TimeoutFilter`: Sets custom timeouts for specific routes
- `PathRewriteFilter`: Rewrites request paths using regex patterns

Filters can be applied globally or to specific routes.

### 5. Security System

The security system provides authentication and authorization:

- **SecurityChain**: Manages a sequence of security providers
- **SecurityProvider**: Interface for authentication mechanisms
- **OidcProvider**: Validates JWT tokens against an OpenID Connect provider

Security providers can be configured to bypass certain routes (e.g., health checks).

### 6. Observability

Foxy includes built-in observability features:

- **Logging**: Structured logging with configurable levels
- **Metrics**: Detailed timing metrics for requests
- **OpenTelemetry**: Distributed tracing integration (optional feature)

### 7. Server

The `ProxyServer` handles the HTTP server implementation:

- Binds to configured address and port
- Processes incoming HTTP requests
- Provides health check endpoints
- Manages graceful shutdown

## Execution Flow

1. **Initialization**:
   - `FoxyLoader` loads configuration from files and environment
   - `ProxyCore` is created with the configuration
   - `PredicateRouter` is initialized with routes from configuration
   - Global filters and security providers are registered

2. **Request Processing**:
   - Incoming HTTP request is received by `ProxyServer`
   - Request is converted to `ProxyRequest`
   - Security chain pre-authentication is applied
   - Global pre-filters are applied
   - Route is selected using `PredicateRouter`
   - Route-specific pre-filters are applied
   - Request is forwarded to the target service
   - Response is received from the target
   - Route-specific post-filters are applied
   - Global post-filters are applied
   - Security chain post-authentication is applied
   - Response is returned to the client

## Usage Modes

### 1. As a Library

Foxy can be embedded in Rust applications as a library:

```rust
use foxy::Foxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let foxy = Foxy::loader()
        .with_env_vars()
        .with_config_file("config.toml")
        .build().await?;

    foxy.start().await?;
    Ok(())
}
```

Key components for library users:
- `FoxyLoader`: Builder pattern for initializing the proxy
- `ConfigProvider`: Interface for custom configuration sources
- `Filter`: Interface for custom request/response processing
- `Predicate`: Interface for custom routing logic
- `SecurityProvider`: Interface for custom authentication mechanisms

### 2. As a Binary

Foxy provides a standalone binary that can be run directly:

```bash
FOXY_CONFIG_FILE=/path/to/config.json foxy
```

The binary:
- Loads configuration from environment variables and files
- Initializes logging based on `RUST_LOG_LEVEL`
- Starts the proxy server
- Handles graceful shutdown on signals

### 3. As a Docker Container

Foxy is available as a multi-architecture Docker image:

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/config.json:/app/config.json:ro" \
  -e FOXY_CONFIG_FILE=/app/config.json \
  johansteffens/foxy:latest
```

The Docker image:
- Is built for both x86_64 and aarch64 architectures
- Uses Alpine Linux for a minimal footprint
- Includes CA certificates for HTTPS connections
- Runs with the OpenTelemetry feature enabled by default

## Extension Points

Foxy is designed to be extended through well-defined traits:

1. **ConfigProvider**: Add custom configuration sources
   ```rust
   #[async_trait::async_trait]
   pub trait ConfigProvider: Send + Sync {
       async fn get(&self, key: &str) -> Result<Option<Value>, ConfigError>;
   }
   ```

2. **Filter**: Create custom request/response processing logic
   ```rust
   #[async_trait::async_trait]
   pub trait Filter: fmt::Debug + Send + Sync {
       fn filter_type(&self) -> FilterType;
       fn name(&self) -> &str;
       async fn pre_filter(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError>;
       async fn post_filter(&self, request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError>;
   }
   ```

3. **Predicate**: Implement custom routing logic
   ```rust
   #[async_trait::async_trait]
   pub trait Predicate: Send + Sync + fmt::Debug {
       async fn matches(&self, request: &ProxyRequest) -> bool;
   }
   ```

4. **SecurityProvider**: Add authentication mechanisms
   ```rust
   #[async_trait::async_trait]
   pub trait SecurityProvider: Send + Sync + fmt::Debug {
       fn name(&self) -> &str;
       fn stage(&self) -> SecurityStage;
       async fn pre_auth(&self, request: ProxyRequest) -> Result<ProxyRequest, ProxyError>;
       async fn post_auth(&self, request: ProxyRequest, response: ProxyResponse) -> Result<ProxyResponse, ProxyError>;
   }
   ```

## Performance Considerations

Foxy is designed for high performance:

- **Zero-Copy Streaming**: Request and response bodies are streamed without buffering
- **Backpressure Support**: Flow control is maintained throughout the pipeline
- **Memory Efficiency**: Memory usage is bound by socket buffers, not request size
- **Async Architecture**: Built on Tokio and Hyper for efficient async I/O
- **Connection Pooling**: HTTP client reuses connections for better performance

## Conclusion

Foxy provides a flexible, extensible HTTP proxy with a focus on configuration-driven behavior and minimal attack surface. Its architecture allows for custom extensions while maintaining high performance and security. The project can be used as a library, standalone binary, or Docker container, making it suitable for a wide range of deployment scenarios.
