# Foxy 🦊

[![CI](https://img.shields.io/github/actions/workflow/status/johan-steffens/foxy/publish.yml)](https://github.com/johan-steffens/foxy/actions/workflows/publish.yml)
[![Crates.io Version](https://img.shields.io/crates/v/foxy-io)](https://crates.io/crates/foxy-io)
[![Crates.io Downloads](https://img.shields.io/crates/d/foxy-io?style=flat-square)](https://crates.io/crates/foxy-io)
[![Crates.io License](https://img.shields.io/github/license/johan-steffens/foxy)](https://github.com/johan-steffens/foxy/blob/main/LICENSE.md)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-blue?style=flat-square)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)

A minimal, configuration-driven, hyper-extendible Rust HTTP proxy library.

## Features

- 🔒 **Security-First Design**: Zero trust by default, configurable validation, header sanitization
- 🧩 **Highly Extensible**: Trait-based middleware, flexible routing, customizable components
- ⚙️ **Configuration Superpowers**: Layered configuration from multiple sources
- 🚀 **Modern Async Architecture**: Built on Tokio and Hyper for high performance
- 📦 **Lightweight Dependencies**: Minimal external dependencies for core functionality
- 🔧 **Developer Experience**: Clear error messages, comprehensive logging, type-safe configuration

## Quickstart

```rust
use foxy::Foxy;

// Create a new Foxy instance with layered configuration
let foxy = Foxy::loader()
    .with_env_vars()                  // Environment variables (highest priority)
    .with_config_file("config.toml")  // File-based config (medium priority)
    .with_config_file("defaults.toml") // Defaults (lowest priority)
    .build().await?;

// Type-safe configuration access
let timeout: u64 = config.get_or_default("proxy.timeout", 30)?;
let host: String = config.get("server.host")?.unwrap_or_else(|| "localhost".to_string());

// Start the proxy server and wait for it to complete
foxy.start().await?;
```

## Core Principles
- **Security**: Secure core routing with opt-in security features via configuration/extensions
- **Extensibility**: Trait-based design for easy extension with minimal core
- **Configuration-Driven**: All non-default behavior controlled via flexible configuration

## Configuration System
Foxy uses a flexible configuration system supporting multiple prioritized sources:
- **Multiple Providers**: File-based (JSON, TOML, YAML) and environment variables
- **Layered Configuration**: Multiple sources with priority order
- **Type-Safe Access**: Convert configuration values to expected types with defaults

### Examples
``` rust
// Load from a file with auto-detected format
let config = Config::default_file("config.toml")?;

// Build a custom layered configuration
let config = Config::builder()
    .with_provider(EnvConfigProvider::default())
    .with_provider(FileConfigProvider::new("config.toml")?)
    .build();
```
## Environment Variables
Environment variables are mapped to configuration keys:
- Variables must start with the prefix (`FOXY_` by default)
- Prefix is stripped and remainder converted to lowercase
- Underscores (`_`) are converted to dots (`.`) for nested access

Examples:
- `FOXY_SERVER_HOST` → `server.host`
- `FOXY_LOGGING_LEVEL` → `logging.level`

## File Configuration
Supported formats:
- JSON (`.json`)
- TOML (`.toml`)
- YAML (`.yaml` or `.yml`, requires the feature) `yaml`

Example `config.toml`:
``` toml
[server]
host = "127.0.0.1"
port = 8080

[proxy]
target = "https://example.com"
```
## Development Status
- [x] Configuration System
- [x] Loader Module
- [x] Core HTTP Proxy
- [ ] Middleware Support
- [ ] Router Implementation
- [ ] Security Features

## License
This project is licensed under [Mozilla Public License Version 2.0](LICENSE.md)

