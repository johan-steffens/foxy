// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! High-level entry-point – "turn the key and go".
//!
//! The [`FoxyLoader`] consumes configuration, builds the predicate-router,
//! wires up the filter graph and returns a single [`ProxyCore`] ready to be
//! passed into [`ProxyServer::serve`].

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use log::LevelFilter;
use serde_json::Value;
use thiserror::Error;

use crate::config::{Config, ConfigError, ConfigProvider, EnvConfigProvider, FileConfigProvider};
use crate::router::{FilterConfig, PredicateRouter, RouteConfig};
use crate::{init_logging, log_error, log_info, logging, Filter, FilterFactory, ProxyError, ProxyServer, ServerConfig};
use crate::core::ProxyCore;
use crate::logging::config::LoggingConfig;
use crate::logging::init_with_config;

/// Errors that can occur during Foxy initialization.
#[derive(Error, Debug)]
pub enum LoaderError {
    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(#[from] ConfigError),

    /// Proxy error
    #[error("proxy error: {0}")]
    ProxyError(#[from] ProxyError),

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
    custom_filters: Vec<Arc<dyn Filter>>,
}

impl Default for FoxyLoader {
    fn default() -> Self {
        Self {
            config_builder: None,
            config_file_path: None,
            use_env_vars: false,
            env_prefix: None,
            custom_filters: Vec::new(),
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

    /// Add a custom filter.
    pub fn with_filter<F: Filter + 'static>(mut self, filter: F) -> Self {
        self.custom_filters.push(Arc::new(filter));
        self
    }

    /// Build and initialize Foxy.
    pub async fn build(self) -> Result<Foxy, LoaderError> {
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

        let config_arc = Arc::new(config);

        // Then initialize the logger
        let log_level = match env::var("RUST_LOG_LEVEL").ok().as_deref() {
            Some("trace") => LevelFilter::Trace,
            Some("debug") => LevelFilter::Debug,
            Some("info") => LevelFilter::Info,
            Some("warn") => LevelFilter::Warn,
            Some("error") => LevelFilter::Error,
            _ => LevelFilter::Info,
        };

        match config_arc.get::<LoggingConfig>("proxy.logging") {
            Ok(Some(logging_config)) => {
                init_with_config(Some(log_level), Some(logging_config));
            }
            Ok(None) => {
                log_info("Startup", "Logging configuration not found. Initializing with default settings.");

                init_logging(Some(log_level));
            }
            Err(e) => {
                log_error("Startup", format!("Failed to read Logging configuration: {}", e));
            }
        }

        crate::info!("Foxy starting up");
        
        #[cfg(feature = "opentelemetry")]
        {
            if let Ok(Some(otel_config)) = config_arc.get::<crate::opentelemetry::OpenTelemetryConfig>("proxy.opentelemetry") {
                crate::info!("OpenTelemetry initialized with endpoint: {} and service name: {}", 
                          otel_config.endpoint, otel_config.service_name);
            }
        }

        // Create the router
        let router = PredicateRouter::new(config_arc.clone()).await?;

        // Create the proxy core
        let proxy_core = ProxyCore::new(config_arc.clone(), Arc::new(router)).await?;

        // Load global filters from configuration
        let global_filters_config: Option<Vec<FilterConfig>> = config_arc.get("proxy.global_filters")?;

        if let Some(global_filters) = global_filters_config {
            for filter_config in global_filters {
                let filter = FilterFactory::create_filter(
                    &filter_config.type_,
                    filter_config.config.clone(),
                )?;
                proxy_core.add_global_filter(filter).await;

                crate::info!("Added global filter: {}", filter_config.type_);
            }
        }

        // Add custom filters
        for filter in self.custom_filters {
            proxy_core.add_global_filter(filter).await;
        }

        // Get server configuration
        let server_config: ServerConfig = config_arc.get_or_default("server", ServerConfig::default())?;

        // Create the proxy server
        let proxy_server = ProxyServer::new(server_config, Arc::new(proxy_core));

        // Create the Foxy instance
        Ok(Foxy {
            config: config_arc,
            server: proxy_server,
        })
    }
}

/// Main Foxy struct that holds the initialized proxy.
#[derive(Debug, Clone)]
pub struct Foxy {
    config: Arc<Config>,
    server: ProxyServer,
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

    /// Start the proxy server.
    pub async fn start(&self) -> Result<(), LoaderError> {
        self.server.start().await.map_err(LoaderError::ProxyError)
    }
}
