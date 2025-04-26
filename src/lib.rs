//! Foxy - A minimal, configuration-driven, hyper-extendible Rust HTTP proxy library
//!
//! Foxy is designed as a drop-in component with configurable behavior. By default,
//! it provides only basic pass-through routing, with all other functionality
//! requiring explicit opt-in via configuration or code extension.
//!
//! # Core Principles
//!
//! - **Security**: Secure core routing with no features enabled by default
//! - **Extensibility**: Design around traits for user extensions
//! - **Configuration**: Drive all non-default behavior via configuration
//! - **Minimal Default**: "Zero-config" results in only basic request forwarding
//!
//! # Configuration System
//!
//! Foxy's configuration system is built for flexibility and extensibility:
//!
//! - **Multiple Configuration Sources**: Load configuration from files (JSON, TOML, YAML)
//!   and environment variables.
//! - **Layered Configuration**: Create a hierarchy of configuration providers with
//!   well-defined priorities.
//! - **Type Safety**: Parse configuration values into the appropriate Rust types.
//! - **Extensibility**: Implement the `ConfigProvider` trait to create custom configuration sources.
//!
//! # Initialization and Usage
//!
//! Foxy is initialized using the `Foxy` loader, which provides a fluent API for configuration:
//!
//! ```rust,no_run
//! use foxy::Foxy;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize with default settings
//!     let foxy = Foxy::loader().build()?;
//!
//!     // Or with custom configuration
//!     let custom_foxy = Foxy::loader()
//!         .with_config_file("config.toml")
//!         .with_env_vars()
//!         .build()?;
//!
//!     // Access configuration values
//!     let host: String = foxy.config().get("server.host")?.unwrap_or_else(|| "localhost".to_string());
//!     let port: u16 = foxy.config().get_or_default("server.port", 8080)?;
//!
//!     println!("Server configured at {}:{}", host, port);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Custom Configuration Providers
//!
//! You can implement the `ConfigProvider` trait to create custom configuration sources:
//!
//! ```rust,no_run
//! use foxy::{Foxy, config::{ConfigProvider, ConfigError}};
//! use serde_json::{Value, json};
//!
//! #[derive(Debug)]
//! struct MyConfigProvider;
//!
//! impl ConfigProvider for MyConfigProvider {
//!     fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
//!         // Custom implementation...
//!         Ok(Some(json!("value")))
//!     }
//!
//!     fn has(&self, key: &str) -> bool {
//!         // Check if the key exists...
//!         true
//!     }
//!
//!     fn provider_name(&self) -> &str {
//!         "my_provider"
//!     }
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let foxy = Foxy::loader()
//!         .with_provider(MyConfigProvider)
//!         .build()?;
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod loader;

// Re-export key types at the crate root for convenience
pub use config::{ConfigProvider, ConfigProviderExt, ConfigError};
pub use loader::{Foxy, FoxyLoader, LoaderError};

// Future modules will be added here as they are implemented:
// pub mod core;
// pub mod middleware;
// pub mod router;
// pub mod security;