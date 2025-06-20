// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Environment variable-based configuration provider implementation.

use std::collections::HashMap;
use std::env;
use serde_json::{Value, json};

use super::ConfigProvider;
use super::ConfigError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use crate::config::ConfigProviderExt;

    #[test]
    fn test_env_provider() {
        // Set some test environment variables
        unsafe {
            env::set_var("FOXY_SERVER_HOST", "localhost");
            env::set_var("FOXY_SERVER_PORT", "9090");
            env::set_var("FOXY_DEBUG", "true");
        }

        let provider = EnvConfigProvider::default();

        assert_eq!(provider.has("server.host"), true);
        assert_eq!(provider.has("nonexistent"), false);

        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "localhost");

        let port: u16 = provider.get("server.port").unwrap().unwrap();
        assert_eq!(port, 9090);

        let debug: bool = provider.get("debug").unwrap().unwrap();
        assert_eq!(debug, true);

        // Clean up
        unsafe {
            env::remove_var("FOXY_SERVER_HOST");
            env::remove_var("FOXY_SERVER_PORT");
            env::remove_var("FOXY_DEBUG");
        }
    }

    #[test]
    fn test_custom_prefix() {
        unsafe {
            env::set_var("CUSTOM_HOST", "customhost");
        }

        let provider = EnvConfigProvider::new("CUSTOM_");

        assert_eq!(provider.has("host"), true);
        let host: String = provider.get("host").unwrap().unwrap();
        assert_eq!(host, "customhost");

        // Clean up
        unsafe {
            env::remove_var("CUSTOM_HOST");
        }
    }

    #[test]
    fn test_cache_refresh() {
        let mut provider = EnvConfigProvider::new("TEST_");

        // Initially there should be no values
        assert_eq!(provider.has("value"), false);

        // Set a value after initialization
        unsafe {
            env::set_var("TEST_VALUE", "42");
        }

        // Should still be false as the cache hasn't been refreshed
        assert_eq!(provider.has("value"), false);

        // Refresh the cache
        provider.refresh_cache();

        // Now it should be available
        assert_eq!(provider.has("value"), true);
        let value: i32 = provider.get("value").unwrap().unwrap();
        assert_eq!(value, 42);

        // Clean up
        unsafe {
            env::remove_var("TEST_VALUE");
        }
    }

    #[test]
    fn test_custom_prefix_comprehensive() {
        // Set some test environment variables with custom prefix
        unsafe {
            env::set_var("MYAPP_DATABASE_HOST", "db.example.com");
            env::set_var("MYAPP_DATABASE_PORT", "5432");
            env::set_var("MYAPP_FEATURE_ENABLED", "true");
        }

        let provider = EnvConfigProvider::new("MYAPP_");

        assert_eq!(provider.has("database.host"), true);
        assert_eq!(provider.has("database.port"), true);
        assert_eq!(provider.has("feature.enabled"), true);
        assert_eq!(provider.has("nonexistent"), false);

        let host: String = provider.get("database.host").unwrap().unwrap();
        assert_eq!(host, "db.example.com");

        let port: u16 = provider.get("database.port").unwrap().unwrap();
        assert_eq!(port, 5432);

        let enabled: bool = provider.get("feature.enabled").unwrap().unwrap();
        assert_eq!(enabled, true);

        // Clean up
        unsafe {
            env::remove_var("MYAPP_DATABASE_HOST");
            env::remove_var("MYAPP_DATABASE_PORT");
            env::remove_var("MYAPP_FEATURE_ENABLED");
        }
    }

    #[test]
    fn test_empty_prefix() {
        // Set some test environment variables without prefix
        unsafe {
            env::set_var("HOST", "localhost");
            env::set_var("PORT", "3000");
        }

        let provider = EnvConfigProvider::new("");

        assert_eq!(provider.has("host"), true);
        assert_eq!(provider.has("port"), true);

        let host: String = provider.get("host").unwrap().unwrap();
        assert_eq!(host, "localhost");

        let port: u16 = provider.get("port").unwrap().unwrap();
        assert_eq!(port, 3000);

        // Clean up
        unsafe {
            env::remove_var("HOST");
            env::remove_var("PORT");
        }
    }

    #[test]
    fn test_complex_nested_keys() {
        unsafe {
            env::set_var("FOXY_DATABASE_CONNECTIONS_PRIMARY_HOST", "db1.example.com");
            env::set_var("FOXY_DATABASE_CONNECTIONS_PRIMARY_PORT", "5432");
            env::set_var("FOXY_DATABASE_CONNECTIONS_SECONDARY_HOST", "db2.example.com");
            env::set_var("FOXY_CACHE_REDIS_URL", "redis://localhost:6379");
        }

        let provider = EnvConfigProvider::default();

        assert_eq!(provider.has("database.connections.primary.host"), true);
        let primary_host: String = provider.get("database.connections.primary.host").unwrap().unwrap();
        assert_eq!(primary_host, "db1.example.com");

        let primary_port: u16 = provider.get("database.connections.primary.port").unwrap().unwrap();
        assert_eq!(primary_port, 5432);

        let secondary_host: String = provider.get("database.connections.secondary.host").unwrap().unwrap();
        assert_eq!(secondary_host, "db2.example.com");

        let redis_url: String = provider.get("cache.redis.url").unwrap().unwrap();
        assert_eq!(redis_url, "redis://localhost:6379");

        // Clean up
        unsafe {
            env::remove_var("FOXY_DATABASE_CONNECTIONS_PRIMARY_HOST");
            env::remove_var("FOXY_DATABASE_CONNECTIONS_PRIMARY_PORT");
            env::remove_var("FOXY_DATABASE_CONNECTIONS_SECONDARY_HOST");
            env::remove_var("FOXY_CACHE_REDIS_URL");
        }
    }

    #[test]
    fn test_different_value_types() {
        unsafe {
            env::set_var("FOXY_STRING_VALUE", "hello world");
            env::set_var("FOXY_INTEGER_VALUE", "42");
            env::set_var("FOXY_FLOAT_VALUE", "3.14");
            env::set_var("FOXY_BOOLEAN_TRUE", "true");
            env::set_var("FOXY_BOOLEAN_FALSE", "false");
            env::set_var("FOXY_ARRAY_VALUE", "[1, 2, 3]");
            env::set_var("FOXY_OBJECT_VALUE", r#"{"key": "value"}"#);
        }

        let provider = EnvConfigProvider::default();

        let string_val: String = provider.get("string.value").unwrap().unwrap();
        assert_eq!(string_val, "hello world");

        let int_val: i32 = provider.get("integer.value").unwrap().unwrap();
        assert_eq!(int_val, 42);

        let float_val: f64 = provider.get("float.value").unwrap().unwrap();
        assert_eq!(float_val, 3.14);

        let bool_true: bool = provider.get("boolean.true").unwrap().unwrap();
        assert_eq!(bool_true, true);

        let bool_false: bool = provider.get("boolean.false").unwrap().unwrap();
        assert_eq!(bool_false, false);

        let array_val: Vec<i32> = provider.get("array.value").unwrap().unwrap();
        assert_eq!(array_val, vec![1, 2, 3]);

        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct TestObject {
            key: String,
        }

        let object_val: TestObject = provider.get("object.value").unwrap().unwrap();
        assert_eq!(object_val.key, "value");

        // Clean up
        unsafe {
            env::remove_var("FOXY_STRING_VALUE");
            env::remove_var("FOXY_INTEGER_VALUE");
            env::remove_var("FOXY_FLOAT_VALUE");
            env::remove_var("FOXY_BOOLEAN_TRUE");
            env::remove_var("FOXY_BOOLEAN_FALSE");
            env::remove_var("FOXY_ARRAY_VALUE");
            env::remove_var("FOXY_OBJECT_VALUE");
        }
    }

    #[test]
    fn test_invalid_json_value() {
        unsafe {
            env::set_var("FOXY_INVALID_JSON", "{invalid json}");
        }

        let provider = EnvConfigProvider::default();

        // Should treat invalid JSON as a string
        let value: String = provider.get("invalid.json").unwrap().unwrap();
        assert_eq!(value, "{invalid json}");

        // Clean up
        unsafe {
            env::remove_var("FOXY_INVALID_JSON");
        }
    }

    #[test]
    fn test_case_sensitivity() {
        unsafe {
            env::set_var("FOXY_UPPER_CASE", "upper");
            env::set_var("foxy_lower_case", "lower"); // This won't match the prefix
        }

        let provider = EnvConfigProvider::default();

        // Should find the uppercase version
        assert_eq!(provider.has("upper.case"), true);
        let value: String = provider.get("upper.case").unwrap().unwrap();
        assert_eq!(value, "upper");

        // Should not find the lowercase version (prefix doesn't match)
        assert_eq!(provider.has("lower.case"), false);

        // Clean up
        unsafe {
            env::remove_var("FOXY_UPPER_CASE");
            env::remove_var("foxy_lower_case");
        }
    }

    #[test]
    fn test_empty_environment() {
        // Create a provider with a prefix that doesn't exist
        let provider = EnvConfigProvider::new("NONEXISTENT_PREFIX_");

        assert_eq!(provider.has("any.key"), false);
        let result: Option<String> = provider.get("any.key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_provider_name() {
        let provider = EnvConfigProvider::default();
        assert_eq!(provider.provider_name(), "env");
    }

    #[test]
    fn test_special_characters_in_values() {
        unsafe {
            env::set_var("FOXY_SPECIAL_CHARS", "value with spaces and symbols: !@#$%^&*()");
            env::set_var("FOXY_UNICODE_VALUE", "Hello 世界 🌍");
            env::set_var("FOXY_NEWLINES", "line1\nline2\nline3");
        }

        let provider = EnvConfigProvider::default();

        let special: String = provider.get("special.chars").unwrap().unwrap();
        assert_eq!(special, "value with spaces and symbols: !@#$%^&*()");

        let unicode: String = provider.get("unicode.value").unwrap().unwrap();
        assert_eq!(unicode, "Hello 世界 🌍");

        let newlines: String = provider.get("newlines").unwrap().unwrap();
        assert_eq!(newlines, "line1\nline2\nline3");

        // Clean up
        unsafe {
            env::remove_var("FOXY_SPECIAL_CHARS");
            env::remove_var("FOXY_UNICODE_VALUE");
            env::remove_var("FOXY_NEWLINES");
        }
    }

    #[test]
    fn test_numeric_string_parsing() {
        unsafe {
            env::set_var("FOXY_ZERO", "0");
            env::set_var("FOXY_NEGATIVE", "-42");
            env::set_var("FOXY_LARGE_NUMBER", "9223372036854775807"); // i64::MAX
            env::set_var("FOXY_DECIMAL", "123.456");
        }

        let provider = EnvConfigProvider::default();

        let zero: i32 = provider.get("zero").unwrap().unwrap();
        assert_eq!(zero, 0);

        let negative: i32 = provider.get("negative").unwrap().unwrap();
        assert_eq!(negative, -42);

        let large: i64 = provider.get("large.number").unwrap().unwrap();
        assert_eq!(large, 9223372036854775807);

        let decimal: f64 = provider.get("decimal").unwrap().unwrap();
        assert_eq!(decimal, 123.456);

        // Clean up
        unsafe {
            env::remove_var("FOXY_ZERO");
            env::remove_var("FOXY_NEGATIVE");
            env::remove_var("FOXY_LARGE_NUMBER");
            env::remove_var("FOXY_DECIMAL");
        }
    }
}