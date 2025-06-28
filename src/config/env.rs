// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Environment variable-based configuration provider implementation.

use serde_json::{Value, json};
use std::collections::HashMap;
use std::env;

use super::ConfigError;
use super::ConfigProvider;

/// Configuration provider that retrieves values from environment variables.
#[derive(Debug)]
pub struct EnvConfigProvider {
    /// Prefix for environment variables (e.g., "FOXY_").
    prefix: String,
    /// Cache of environment variables that match the prefix.
    cache: HashMap<String, String>,
}

impl EnvConfigProvider {
    /// Create a new environment variable configuration provider with the specified prefix.
    pub fn new(prefix: &str) -> Self {
        let mut provider = Self {
            prefix: prefix.to_string(),
            cache: HashMap::new(),
        };

        // Pre-load all environment variables with the specified prefix
        provider.refresh_cache();

        provider
    }

    /// Refresh the cache of environment variables.
    pub fn refresh_cache(&mut self) {
        self.cache.clear();

        for (key, value) in env::vars() {
            if key.starts_with(&self.prefix) {
                // Strip the prefix and convert to lowercase for consistent key lookup
                let config_key = key[self.prefix.len()..].to_lowercase();
                // Convert underscores to dots for nested keys (e.g., FOXY_SERVER_HOST -> server.host)
                let config_key = config_key.replace('_', ".");

                self.cache.insert(config_key, value);
            }
        }
    }

    /// Parse a string value into a JSON Value.
    fn parse_value_to_json(&self, value: &str) -> Result<Value, ConfigError> {
        // Try to parse as JSON first
        if let Ok(json_value) = serde_json::from_str(value) {
            return Ok(json_value);
        }

        // If JSON parsing fails, try to determine the type and convert

        // Try boolean
        if value.eq_ignore_ascii_case("true") {
            return Ok(json!(true));
        } else if value.eq_ignore_ascii_case("false") {
            return Ok(json!(false));
        }

        // Try number
        if let Ok(int_val) = value.parse::<i64>() {
            return Ok(json!(int_val));
        }

        if let Ok(float_val) = value.parse::<f64>() {
            return Ok(json!(float_val));
        }

        // Default to string
        Ok(json!(value))
    }
}

impl Default for EnvConfigProvider {
    fn default() -> Self {
        Self::new("FOXY_")
    }
}

impl ConfigProvider for EnvConfigProvider {
    fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
        match self.cache.get(key) {
            Some(value) => self.parse_value_to_json(value).map(Some),
            None => Ok(None),
        }
    }

    fn has(&self, key: &str) -> bool {
        self.cache.contains_key(key)
    }

    fn provider_name(&self) -> &str {
        "env"
    }
}
