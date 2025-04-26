# Foxy

A minimal, configuration-driven, hyper-extendible Rust HTTP proxy library.

## Features

🔒 **Security-First Design**
- Zero trust by default with opt-in security features
- Configurable request/response validation
- Header sanitization and injection protection

🧩 **Highly Extensible**
- Trait-based plugin architecture for custom middleware
- Flexible routing with path, method, and header matching
- Easy to extend with your own components

⚙️ **Configuration Superpowers**
```rust
// Load layered configuration from multiple sources
let foxy = Foxy::loader()
    .with_env_vars()                // Environment variables (highest priority)
    .with_config_file("config.toml") // File-based config (medium priority)
    .with_config_file("defaults.toml") // Defaults (lowest priority)
    .build()?;
```

🚀 **Modern Async Architecture**
- Built on Tokio for high-performance async I/O
- Hyper-powered HTTP implementation
- Non-blocking request processing

📦 **Lightweight Dependencies**
- **tokio**: Async runtime with excellent performance characteristics
- **hyper**: Battle-tested HTTP implementation
- **serde**: Flexible serialization/deserialization
- Minimal external dependencies for core functionality

🔧 **Developer Experience**
- Clear error messages with context
- Comprehensive logging
- Type-safe configuration access
```rust
// Type-safe configuration with fallbacks
let timeout: u64 = config.get_or_default("proxy.timeout", 30)?;
let host: String = config.get("server.host")?.unwrap_or_else(|| "localhost".to_string());
```

## Core Principles

- **Security**: Implements secure core routing. No features (header injection, validation) enabled by default. Security enhancements are strictly opt-in via configuration/extensions.
- **Extensibility**: Design around traits (e.g., Middleware, Router) for user extensions. Maintains a minimal core; facilitates composable additions.
- **Configuration**: Drives all non-default behavior via configuration.
  - **Minimal Default**: "Zero-config" or base config results only in basic request forwarding.
  - **Explicit Enhancement**: All features require explicit activation via layered configuration (defaults overridden by files/env/code).

## Configuration System

Foxy's configuration system is designed to be extensible and flexible, supporting multiple configuration sources with a prioritized hierarchy.

### Key Features

- **Multiple Providers**: Support for file-based (JSON, TOML, YAML) and environment variables
- **Layered Configuration**: Configure using multiple sources with priority order
- **Extensible**: Easily create custom configuration providers
- **Type-Safe**: Convert configuration values to the expected types
- **Default Values**: Specify fallbacks for missing configuration
- **Trait-Based Design**: Object-safe traits for dynamic dispatch

### Usage Examples

#### Load Configuration from a File

```rust
use foxy::config::Config;

// Load from a file with auto-detected format (based on extension)
let config = Config::default_file("config.toml")?;

// Get typed values with defaults
let host: String = config.get("server.host")?.unwrap_or_else(|| "localhost".to_string());
let port: u16 = config.get_or_default("server.port", 8080)?;
```

#### Build a Custom Configuration

```rust
use foxy::config::{Config, FileConfigProvider, EnvConfigProvider};

// Create a layered configuration with multiple providers
let config = Config::builder()
// Environment variables (highest priority)
.with_provider(EnvConfigProvider::default())
// File configuration (fallback)
.with_provider(FileConfigProvider::new("config.toml")?)
.build();
```

### Architecture

The configuration system uses a split-trait approach to support both dynamic dispatch and generic type parameters:

- `ConfigProvider`: An object-safe trait that all configuration providers must implement, supporting dynamic dispatch
- `ConfigProviderExt`: An extension trait that provides typed access to configuration values

This design allows for a flexible system where providers can be used as trait objects while still maintaining type safety.

## Loader Module

The Foxy loader is the main entry point for initializing and configuring the library. It provides a fluent builder API for setting up Foxy with the desired configuration.

### Key Features

- **Simple Initialization**: Start Foxy with default settings or custom configuration
- **Fluent API**: Chain method calls for a clean and readable setup
- **Flexible Configuration**: Use files, environment variables, or custom providers
- **Extensible**: Add custom configuration providers

### Usage Examples

#### Initialize with Defaults

```rust
use foxy::Foxy;

// Create a new Foxy instance with default settings
let foxy = Foxy::loader().build()?;
```

#### Initialize with a Configuration File

```rust
use foxy::Foxy;

// Create a new Foxy instance with configuration from a file
let foxy = Foxy::loader()
.with_config_file("config.toml")
.build()?;
```

#### Initialize with Environment Variables

```rust
use foxy::Foxy;

// Create a new Foxy instance that reads from environment variables
let foxy = Foxy::loader()
.with_env_vars()           // Use default prefix "FOXY_"
.build()?;

// Or with a custom prefix
let foxy = Foxy::loader()
.with_env_prefix("MY_APP_")
.build()?;
```

#### Initialize with a Custom Provider

```rust
use foxy::{Foxy, ConfigProvider, ConfigError};
use serde_json::{Value, json};

// Define a custom configuration provider
#[derive(Debug)]
struct MyProvider;

impl ConfigProvider for MyProvider {
  fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
    match key {
      "my.setting" => Ok(Some(json!("my value"))),
      _ => Ok(None),
    }
  }

  fn has(&self, key: &str) -> bool {
    key == "my.setting"
  }

  fn provider_name(&self) -> &str {
    "my_provider"
  }
}

// Create a new Foxy instance with the custom provider
let foxy = Foxy::loader()
.with_provider(MyProvider)
.build()?;
```

#### Combined Configuration with Priority

```rust
use foxy::Foxy;

// Create a new Foxy instance with multiple configuration sources
// Sources are checked in the order they are added (first has highest priority)
let foxy = Foxy::loader()
.with_env_vars()                     // Highest priority
.with_config_file("config.toml")     // Medium priority
.with_config_file("defaults.toml")   // Lowest priority
.build()?;
```

### Environment Variables

Environment variable names are mapped to configuration keys using the following rules:

- Variables must start with the prefix (`FOXY_` by default)
- The prefix is stripped and the remainder is converted to lowercase
- Underscores (`_`) are converted to dots (`.`) for nested access

Examples:
- `FOXY_SERVER_HOST` → `server.host`
- `FOXY_LOGGING_LEVEL` → `logging.level`
- `FOXY_DEBUG` → `debug`

### File Configuration

Supported file formats:
- JSON (`.json` extension)
- TOML (`.toml` extension)
- YAML (`.yaml` or `.yml` extension, requires the `yaml` feature)

Configuration files use a nested structure that can be accessed using dot notation:

```toml
# Example config.toml
[server]
host = "127.0.0.1"
port = 8080

[proxy]
target = "https://example.com"
```

This can be accessed as `server.host`, `server.port`, and `proxy.target`.

## Development Status

- [x] Configuration System
- [x] Loader Module
- [ ] Core HTTP Proxy
- [ ] Middleware Support
- [ ] Router Implementation
- [ ] Security Features

## License

This project is licensed under [Mozilla Public License Version 2.0](LICENSE.md)
