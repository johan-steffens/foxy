// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proxy configuration module.

use serde::{Deserialize, Serialize};
use crate::logging::config::LoggingConfig;

/// Main proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,
    
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
    
    // Other proxy configuration fields can be added here
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on
    #[serde(default = "default_listen")]
    pub listen: String,
    
    /// Maximum body size in bytes
    #[serde(default = "default_body_limit")]
    pub body_limit: usize,
    
    /// Maximum header size in bytes
    #[serde(default = "default_header_limit")]
    pub header_limit: usize,
}

fn default_listen() -> String {
    "[::]:8080".to_string()
}

fn default_body_limit() -> usize {
    5 * 1024 * 1024 // 5MB
}

fn default_header_limit() -> usize {
    256 * 1024 // 256KB
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            body_limit: default_body_limit(),
            header_limit: default_header_limit(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}
