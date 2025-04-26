// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Loader module for Foxy.
//!
//! This module provides the entry point for initializing and configuring
//! the Foxy proxy library. It allows users to start Foxy with default settings
//! or customize it by providing their own configuration.

use std::sync::Arc;
use thiserror::Error;

use crate::config::{Config, ConfigError, ConfigProvider, EnvConfigProvider, FileConfigProvider};

/// Errors that can occur during Foxy initialization.
#[derive(Error, Debug)]
pub enum LoaderError {
    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(#[from] ConfigError),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Builder for initializing and configuring Foxy.
#[derive(Debug)]
pub struct FoxyLoader {
    config_builder: Option<Config>,
    config_file_path: Option<String>,
    use_env_vars: bool,
    env_prefix: Option<String>,
}

impl Default for FoxyLoader {
    fn default() -> Self {
        Self {
            config_builder: None,
            config_file_path: None,
            use_env_vars: false,
            env_prefix: None,
        }
    }
}

impl FoxyLoader {
    /// Create a new Foxy loader with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom configuration to use.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config_builder = Some(config);
        self
    }

    /// Set a configuration file to load.
    pub fn with_config_file(mut self, file_path: &str) -> Self {
        self.config_file_path = Some(file_path.to_string());
        self
    }

    /// Enable environment variable configuration.
    pub fn with_env_vars(mut self) -> Self {
        self.use_env_vars = true;
        self
    }

    /// Set a custom prefix for environment variables (default is "FOXY_").
    pub fn with_env_prefix(mut self, prefix: &str) -> Self {
        self.env_prefix = Some(prefix.to_string());
        self.use_env_vars = true;
        self
    }

    /// Add a custom configuration provider.
    pub fn with_provider<P: ConfigProvider + 'static>(self, provider: P) -> Self {
        let config_builder = match self.config_builder {
            Some(_) => Config::builder().with_provider(provider),
            None => Config::builder().with_provider(provider),
        };

        Self {
            config_builder: Some(config_builder.build()),
            ..self
        }
    }

    /// Build and initialize Foxy.
    pub fn build(self) -> Result<Foxy, LoaderError> {
        // Build the configuration
        let config = if let Some(config) = self.config_builder {
            config
        } else {
            let mut config_builder = Config::builder();

            // Add environment variable provider if enabled
            if self.use_env_vars {
                let env_provider = match self.env_prefix {
                    Some(prefix) => EnvConfigProvider::new(&prefix),
                    None => EnvConfigProvider::default(),
                };
                config_builder = config_builder.with_provider(env_provider);
            }

            // Add file configuration provider if specified
            if let Some(file_path) = self.config_file_path {
                match FileConfigProvider::new(&file_path) {
                    Ok(file_provider) => {
                        config_builder = config_builder.with_provider(file_provider);
                    },
                    Err(e) => {
                        return Err(LoaderError::ConfigError(e));
                    }
                }
            }

            config_builder.build()
        };

        // Create the Foxy instance
        Ok(Foxy {
            config: Arc::new(config),
        })
    }
}

/// Main Foxy struct that holds the initialized proxy.
#[derive(Debug, Clone)]
pub struct Foxy {
    config: Arc<Config>,
}

impl Foxy {
    /// Create a new loader for initializing Foxy.
    pub fn loader() -> FoxyLoader {
        FoxyLoader::new()
    }

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    // TODO: Add methods for starting the proxy server, registering middleware, etc.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_loader() {
        let foxy = Foxy::loader().build().unwrap();
        assert!(Arc::strong_count(&foxy.config) == 1);
    }

    #[test]
    fn test_with_env_vars() {
        unsafe {
            env::set_var("FOXY_TEST_KEY", "test_value");
        }

        let foxy = Foxy::loader()
            .with_env_vars()
            .build()
            .unwrap();

        let value: Option<String> = foxy.config().get("test.key").unwrap();

        unsafe {
            env::remove_var("FOXY_TEST_KEY");
        }

        assert_eq!(value, Some("test_value".to_string()));
    }

    #[test]
    fn test_with_config_file() {
        // Note: This test assumes the existence of a configuration file
        // For a more robust test, we could create a temporary file

        let result = Foxy::loader()
            .with_config_file("nonexistent_file.toml")
            .build();

        // Should fail because the file doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_provider() {
        use crate::config::{ConfigProvider, ConfigError};
        use serde_json::{Value, json};

        #[derive(Debug)]
        struct TestProvider;

        impl ConfigProvider for TestProvider {
            fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
                if key == "test.key" {
                    Ok(Some(json!("custom_value")))
                } else {
                    Ok(None)
                }
            }

            fn has(&self, key: &str) -> bool {
                key == "test.key"
            }

            fn provider_name(&self) -> &str {
                "test"
            }
        }

        let foxy = Foxy::loader()
            .with_provider(TestProvider)
            .build()
            .unwrap();

        let value: Option<String> = foxy.config().get("test.key").unwrap();
        assert_eq!(value, Some("custom_value".to_string()));
    }
}