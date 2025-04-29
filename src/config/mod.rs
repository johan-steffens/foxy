// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Configuration module for Foxy.
//!
//! This module provides extensible configuration capabilities with
//! implementations for file-based and environment-variable based configuration.
//!
//! # Architecture
//!
//! The configuration system is built around the following components:
//!
//! * **`ConfigProvider` trait**: The core interface that all configuration sources must implement.
//! * **`Config` struct**: The main configuration aggregator that manages multiple providers.
//! * **`ConfigBuilder` struct**: Builder pattern for creating `Config` instances.
//! * **Provider implementations**:
//!   * `FileConfigProvider`: Loads configuration from JSON, TOML, or YAML files.
//!   * `EnvConfigProvider`: Loads configuration from environment variables.
//!
//! # Design Principles
//!
//! * **Extensibility**: New configuration sources can be added by implementing the `ConfigProvider` trait.
//! * **Layered Configuration**: Multiple providers can be used with a clear priority order.
//! * **Type Safety**: Configuration values are parsed into the appropriate Rust types.
//! * **Minimal Default**: The base configuration provides only essential functionality.
//!
//! ```

mod file;
mod env;
pub mod error;

pub use error::ConfigError;
pub use file::FileConfigProvider;
pub use env::EnvConfigProvider;

use std::fmt::Debug;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Core configuration provider trait that all configuration sources must implement.
/// This trait is object-safe since it doesn't contain generic methods.
pub trait ConfigProvider: Debug + Send + Sync {
    /// Check if the configuration provider has a value for the given key.
    fn has(&self, key: &str) -> bool;

    /// Get the name of the configuration provider for debugging purposes.
    fn provider_name(&self) -> &str;

    /// Get a raw configuration value by key.
    /// Returns a JSON Value that can be later deserialized into specific types.
    fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError>;
}

/// Extension trait for ConfigProvider that provides methods for typed access.
/// This trait is not object-safe because it has generic methods.
pub trait ConfigProviderExt: ConfigProvider {
    /// Get a configuration value by key and deserialize it to the specified type.
    fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, ConfigError> {
        match self.get_raw(key)? {
            Some(value) => {
                serde_json::from_value(value)
                    .map(Some)
                    .map_err(|e| ConfigError::ParseError(format!("failed to deserialize '{}': {}", key, e)))
            },
            None => Ok(None),
        }
    }
}

// Implement ConfigProviderExt for any type that implements ConfigProvider
impl<T: ConfigProvider> ConfigProviderExt for T {}

/// Builder for the configuration system.
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    providers: Vec<Arc<dyn ConfigProvider>>,
}

impl ConfigBuilder {
    /// Create a new configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a configuration provider.
    pub fn with_provider<P: ConfigProvider + 'static>(mut self, provider: P) -> Self {
        self.providers.push(Arc::new(provider));
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Config {
        Config {
            providers: self.providers,
        }
    }
}

/// Main configuration struct that holds all providers and handles retrieving values.
#[derive(Debug, Clone)]
pub struct Config {
    providers: Vec<Arc<dyn ConfigProvider>>,
}

impl Config {
    /// Create a new configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Get a raw configuration value.
    fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
        for provider in &self.providers {
            if provider.has(key) {
                return provider.get_raw(key);
            }
        }
        Ok(None)
    }

    /// Get a configuration value by key, checking all providers in the order they were added.
    /// Returns the first value found.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, ConfigError> {
        match self.get_raw(key)? {
            Some(value) => {
                serde_json::from_value(value)
                    .map(Some)
                    .map_err(|e| ConfigError::ParseError(format!("failed to deserialize '{}': {}", key, e)))
            },
            None => Ok(None),
        }
    }

    /// Get a configuration value by key with a default fallback value.
    pub fn get_or_default<T: DeserializeOwned>(&self, key: &str, default: T) -> Result<T, ConfigError> {
        match self.get(key)? {
            Some(value) => Ok(value),
            None => Ok(default),
        }
    }

    /// Create a default configuration using the file-based provider.
    pub fn default_file(file_path: &str) -> Result<Self, ConfigError> {
        let provider = FileConfigProvider::new(file_path)?;
        Ok(Self::builder().with_provider(provider).build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_pattern() {
        let config = Config::builder()
            .with_provider(MockProvider::new("mock1"))
            .with_provider(MockProvider::new("mock2"))
            .build();

        assert_eq!(config.providers.len(), 2);
    }

    #[derive(Debug)]
    struct MockProvider {
        name: String,
    }

    impl MockProvider {
        fn new(name: &str) -> Self {
            Self { name: name.to_string() }
        }
    }

    impl ConfigProvider for MockProvider {
        fn get_raw(&self, _key: &str) -> Result<Option<Value>, ConfigError> {
            Ok(None)
        }

        fn has(&self, _key: &str) -> bool {
            false
        }

        fn provider_name(&self) -> &str {
            &self.name
        }
    }
}