// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod config_tests {
    #[cfg(feature = "vault-config")]
    use crate::config::VaultConfigProvider;
    use crate::config::file::FileFormat;
    use crate::config::proxy::{ProxyConfig, ServerConfig};
    use crate::config::{
        Config, ConfigBuilder, ConfigError, ConfigProvider, ConfigProviderExt, EnvConfigProvider,
        FileConfigProvider,
    };
    use serde_json;
    use serde_json::Value;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    // Simple mock config provider for testing
    #[derive(Debug)]
    struct MockConfigProvider {
        values: serde_json::Map<String, Value>,
        name: String,
    }

    impl MockConfigProvider {
        fn new(name: &str, _priority: usize) -> Self {
            let mut values = serde_json::Map::new();
            values.insert("server.port".to_string(), serde_json::json!(8080));
            values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));
            Self {
                values,
                name: name.to_string(),
            }
        }
    }

    impl ConfigProvider for MockConfigProvider {
        fn has(&self, key: &str) -> bool {
            self.values.contains_key(key)
        }

        fn provider_name(&self) -> &str {
            &self.name
        }

        fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
            Ok(self.values.get(key).cloned())
        }
    }

    #[test]
    fn test_config_provider() {
        let provider = MockConfigProvider::new("test", 0);

        assert!(provider.has("server.port"));
        assert!(!provider.has("nonexistent.key"));

        let port = provider.get_raw("server.port").unwrap().unwrap();
        assert_eq!(port, serde_json::json!(8080));

        let host = provider.get_raw("server.host").unwrap().unwrap();
        assert_eq!(host, serde_json::json!("127.0.0.1"));

        let nonexistent = provider.get_raw("nonexistent.key").unwrap();
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_config_builder() {
        // Create two providers with different priorities
        let provider1 = MockConfigProvider::new("provider1", 0);
        let mut provider2 = MockConfigProvider::new("provider2", 1);

        // Override a value in the second provider
        provider2
            .values
            .insert("server.port".to_string(), serde_json::json!(9000));

        // Build config with both providers
        let config = Config::builder()
            .with_provider(provider1)
            .with_provider(provider2)
            .build();

        // The second provider should take precedence
        let port = config.get::<u64>("server.port").unwrap().unwrap();
        assert_eq!(port, 9000);

        // Values not overridden should still be available
        let host = config.get::<String>("server.host").unwrap().unwrap();
        assert_eq!(host, "127.0.0.1");
    }

    #[test]
    fn test_config_get_or_default() {
        let provider = MockConfigProvider::new("test", 0);
        let config = Config::builder().with_provider(provider).build();

        // Existing value
        let port = config.get_or_default("server.port", 1234).unwrap();
        assert_eq!(port, 8080);

        // Default value for non-existent key
        let timeout = config.get_or_default("server.timeout", 30).unwrap();
        assert_eq!(timeout, 30);
    }

    #[test]
    fn test_config_provider_priority() {
        // Create providers with different priorities
        let mut provider1 = MockConfigProvider::new("low-priority", 0);
        provider1
            .values
            .insert("shared.key".to_string(), serde_json::json!("low-value"));

        let mut provider2 = MockConfigProvider::new("high-priority", 10);
        provider2
            .values
            .insert("shared.key".to_string(), serde_json::json!("high-value"));

        let config = Config::builder()
            .with_provider(provider1)
            .with_provider(provider2)
            .build();

        // Higher priority provider should win
        let value = config.get::<String>("shared.key").unwrap().unwrap();
        assert_eq!(value, "high-value");
    }

    #[test]
    fn test_config_type_conversion() {
        let provider = MockConfigProvider::new("test", 0);
        let config = Config::builder().with_provider(provider).build();

        // Test different type conversions
        let port_u64 = config.get::<u64>("server.port").unwrap().unwrap();
        assert_eq!(port_u64, 8080);

        let port_u16 = config.get::<u16>("server.port").unwrap().unwrap();
        assert_eq!(port_u16, 8080);

        let host_string = config.get::<String>("server.host").unwrap().unwrap();
        assert_eq!(host_string, "127.0.0.1");
    }

    #[test]
    fn test_config_invalid_type_conversion() {
        let mut provider = MockConfigProvider::new("test", 0);
        provider.values.insert(
            "invalid.number".to_string(),
            serde_json::json!("not-a-number"),
        );

        let config = Config::builder().with_provider(provider).build();

        // Should fail to convert string to number
        let result = config.get::<u64>("invalid.number");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_nested_keys() {
        let mut provider = MockConfigProvider::new("test", 0);
        provider.values.insert(
            "database.connection.host".to_string(),
            serde_json::json!("db.example.com"),
        );
        provider.values.insert(
            "database.connection.port".to_string(),
            serde_json::json!(5432),
        );

        let config = Config::builder().with_provider(provider).build();

        let host = config
            .get::<String>("database.connection.host")
            .unwrap()
            .unwrap();
        assert_eq!(host, "db.example.com");

        let port = config
            .get::<u16>("database.connection.port")
            .unwrap()
            .unwrap();
        assert_eq!(port, 5432);
    }

    #[test]
    fn test_config_array_values() {
        let mut provider = MockConfigProvider::new("test", 0);
        provider.values.insert(
            "servers".to_string(),
            serde_json::json!(["server1", "server2", "server3"]),
        );

        let config = Config::builder().with_provider(provider).build();

        let servers = config.get::<Vec<String>>("servers").unwrap().unwrap();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "server1");
        assert_eq!(servers[1], "server2");
        assert_eq!(servers[2], "server3");
    }

    #[test]
    fn test_config_object_values() {
        let mut provider = MockConfigProvider::new("test", 0);
        let server_config = serde_json::json!({
            "host": "localhost",
            "port": 8080,
            "ssl": true
        });
        provider.values.insert("server".to_string(), server_config);

        let config = Config::builder().with_provider(provider).build();

        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct ServerConfig {
            host: String,
            port: u16,
            ssl: bool,
        }

        let server = config.get::<ServerConfig>("server").unwrap().unwrap();
        assert_eq!(server.host, "localhost");
        assert_eq!(server.port, 8080);
        assert!(server.ssl);
    }

    #[test]
    fn test_config_boolean_values() {
        let mut provider = MockConfigProvider::new("test", 0);
        provider
            .values
            .insert("feature.enabled".to_string(), serde_json::json!(true));
        provider
            .values
            .insert("feature.disabled".to_string(), serde_json::json!(false));

        let config = Config::builder().with_provider(provider).build();

        let enabled = config.get::<bool>("feature.enabled").unwrap().unwrap();
        assert!(enabled);

        let disabled = config.get::<bool>("feature.disabled").unwrap().unwrap();
        assert!(!disabled);
    }

    #[test]
    fn test_config_empty_provider() {
        let provider = MockConfigProvider {
            values: serde_json::Map::new(),
            name: "empty".to_string(),
        };

        let config = Config::builder().with_provider(provider).build();

        let result = config.get::<String>("nonexistent.key");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_config_provider_name() {
        let provider = MockConfigProvider::new("test-provider", 0);
        assert_eq!(provider.provider_name(), "test-provider");
    }

    #[test]
    fn test_config_provider_has() {
        let provider = MockConfigProvider::new("test", 0);

        assert!(provider.has("server.port"));
        assert!(provider.has("server.host"));
        assert!(!provider.has("nonexistent.key"));
    }

    #[test]
    fn test_config_get_raw_error() {
        #[derive(Debug)]
        struct ErrorProvider;

        impl ConfigProvider for ErrorProvider {
            fn has(&self, _key: &str) -> bool {
                true
            }

            fn provider_name(&self) -> &str {
                "error-provider"
            }

            fn get_raw(&self, _key: &str) -> Result<Option<serde_json::Value>, ConfigError> {
                Err(ConfigError::ParseError("Simulated error".to_string()))
            }
        }

        let config = Config::builder().with_provider(ErrorProvider).build();

        let result = config.get::<String>("any.key");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_default_file() {
        use std::fs::File;
        use std::io::Write;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.json");

        let content = r#"{
            "server": {
                "host": "localhost",
                "port": 9090
            },
            "debug": true
        }"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let config = Config::default_file(file_path.to_str().unwrap()).unwrap();

        let host: String = config.get("server.host").unwrap().unwrap();
        assert_eq!(host, "localhost");

        let port: u16 = config.get("server.port").unwrap().unwrap();
        assert_eq!(port, 9090);

        let debug: bool = config.get("debug").unwrap().unwrap();
        assert!(debug);
    }

    #[test]
    fn test_config_default_file_error() {
        let result = Config::default_file("/nonexistent/path/config.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_builder_new() {
        let builder = ConfigBuilder::new();
        assert_eq!(builder.providers.len(), 0);

        let config = builder.build();
        assert_eq!(config.providers.len(), 0);
    }

    #[test]
    fn test_config_builder_default() {
        let builder = ConfigBuilder::default();
        assert_eq!(builder.providers.len(), 0);
    }

    #[test]
    fn test_config_builder_multiple_providers() {
        let provider1 = MockConfigProvider::new("provider1", 1);
        let provider2 = MockConfigProvider::new("provider2", 2);
        let provider3 = MockConfigProvider::new("provider3", 3);

        let config = ConfigBuilder::new()
            .with_provider(provider1)
            .with_provider(provider2)
            .with_provider(provider3)
            .build();

        assert_eq!(config.providers.len(), 3);
    }

    #[test]
    fn test_config_clone() {
        let provider = MockConfigProvider::new("test", 0);
        let config = Config::builder().with_provider(provider).build();

        let cloned_config = config.clone();
        assert_eq!(cloned_config.providers.len(), config.providers.len());

        // Both configs should work independently
        let value1: String = config.get("server.host").unwrap().unwrap();
        let value2: String = cloned_config.get("server.host").unwrap().unwrap();
        assert_eq!(value1, value2);
    }

    #[test]
    fn test_config_provider_ext_get() {
        let provider = MockConfigProvider::new("test", 0);

        // Existing key should return the value
        let port: Option<u16> = provider.get("server.port").unwrap();
        assert_eq!(port, Some(8080));

        // Non-existing key should return None
        let timeout: Option<u32> = provider.get("timeout").unwrap();
        assert_eq!(timeout, None);
    }

    #[test]
    fn test_config_provider_ext_error_handling() {
        #[derive(Debug)]
        struct ErrorProvider;

        impl ConfigProvider for ErrorProvider {
            fn has(&self, _key: &str) -> bool {
                true
            }

            fn provider_name(&self) -> &str {
                "error-provider"
            }

            fn get_raw(&self, _key: &str) -> Result<Option<serde_json::Value>, ConfigError> {
                Err(ConfigError::ParseError("Simulated error".to_string()))
            }
        }

        let provider = ErrorProvider;

        let result = provider.get::<String>("any.key");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_provider_ext_type_conversion_error() {
        let mut provider = MockConfigProvider::new("test", 0);
        provider.values.insert(
            "invalid.number".to_string(),
            serde_json::json!("not_a_number"),
        );

        let result = provider.get::<u32>("invalid.number");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_provider_ext_null_values() {
        let mut provider = MockConfigProvider::new("test", 0);
        provider
            .values
            .insert("null.value".to_string(), serde_json::json!(null));

        // Null values should cause a deserialization error when trying to convert to a specific type
        let result: Result<Option<String>, ConfigError> = provider.get("null.value");
        assert!(result.is_err());

        // But we can check if the key exists
        assert!(provider.has("null.value"));

        // And get the raw value
        let raw_value = provider.get_raw("null.value").unwrap();
        assert!(raw_value.is_some());
        assert!(raw_value.unwrap().is_null());
    }

    #[test]
    fn test_config_provider_debug() {
        let provider = MockConfigProvider::new("test-provider", 0);
        let debug_str = format!("{provider:?}");
        assert!(debug_str.contains("MockConfigProvider"));
        assert!(debug_str.contains("test-provider"));
    }

    #[test]
    fn test_config_builder_debug() {
        let provider = MockConfigProvider::new("test", 0);
        let builder = ConfigBuilder::new().with_provider(provider);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ConfigBuilder"));
    }

    #[test]
    fn test_config_debug() {
        let provider = MockConfigProvider::new("test", 0);
        let config = Config::builder().with_provider(provider).build();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("Config"));
    }

    /* Environment tests */

    #[test]
    fn test_env_provider() {
        // Set some test environment variables
        unsafe {
            env::set_var("FOXY_SERVER_HOST", "localhost");
            env::set_var("FOXY_SERVER_PORT", "9090");
            env::set_var("FOXY_DEBUG", "true");
        }

        let provider = EnvConfigProvider::default();

        assert!(provider.has("server.host"));
        assert!(!provider.has("nonexistent"));

        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "localhost");

        let port: u16 = provider.get("server.port").unwrap().unwrap();
        assert_eq!(port, 9090);

        let debug: bool = provider.get("debug").unwrap().unwrap();
        assert!(debug);

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

        assert!(provider.has("host"));
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
        assert!(!provider.has("value"));

        // Set a value after initialization
        unsafe {
            env::set_var("TEST_VALUE", "42");
        }

        // Should still be false as the cache hasn't been refreshed
        assert!(!provider.has("value"));

        // Refresh the cache
        provider.refresh_cache();

        // Now it should be available
        assert!(provider.has("value"));
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

        assert!(provider.has("database.host"));
        assert!(provider.has("database.port"));
        assert!(provider.has("feature.enabled"));
        assert!(!provider.has("nonexistent"));

        let host: String = provider.get("database.host").unwrap().unwrap();
        assert_eq!(host, "db.example.com");

        let port: u16 = provider.get("database.port").unwrap().unwrap();
        assert_eq!(port, 5432);

        let enabled: bool = provider.get("feature.enabled").unwrap().unwrap();
        assert!(enabled);

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

        assert!(provider.has("host"));
        assert!(provider.has("port"));

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
            env::set_var(
                "FOXY_DATABASE_CONNECTIONS_SECONDARY_HOST",
                "db2.example.com",
            );
            env::set_var("FOXY_CACHE_REDIS_URL", "redis://localhost:6379");
        }

        let provider = EnvConfigProvider::default();

        assert!(provider.has("database.connections.primary.host"));
        let primary_host: String = provider
            .get("database.connections.primary.host")
            .unwrap()
            .unwrap();
        assert_eq!(primary_host, "db1.example.com");

        let primary_port: u16 = provider
            .get("database.connections.primary.port")
            .unwrap()
            .unwrap();
        assert_eq!(primary_port, 5432);

        let secondary_host: String = provider
            .get("database.connections.secondary.host")
            .unwrap()
            .unwrap();
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
    #[allow(clippy::approx_constant)]
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
        assert!(bool_true);

        let bool_false: bool = provider.get("boolean.false").unwrap().unwrap();
        assert!(!bool_false);

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
        assert!(provider.has("upper.case"));
        let value: String = provider.get("upper.case").unwrap().unwrap();
        assert_eq!(value, "upper");

        // Should not find the lowercase version (prefix doesn't match)
        assert!(!provider.has("lower.case"));

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

        assert!(!provider.has("any.key"));
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
            env::set_var(
                "FOXY_SPECIAL_CHARS",
                "value with spaces and symbols: !@#$%^&*()",
            );
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
        assert_eq!(large, 9_223_372_036_854_775_807);

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

    /* Error tests */

    use std::error::Error;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn test_config_error_not_found() {
        let error = ConfigError::NotFound;
        assert_eq!(error.to_string(), "configuration key not found");
    }

    #[test]
    fn test_config_error_parse_error() {
        let error = ConfigError::ParseError("invalid JSON".to_string());
        assert_eq!(
            error.to_string(),
            "failed to parse configuration: invalid JSON"
        );
    }

    #[test]
    fn test_config_error_io_error() {
        let io_error = IoError::new(ErrorKind::NotFound, "file not found");
        let error = ConfigError::IoError(io_error);
        assert!(error.to_string().contains("IO error"));
        assert!(error.to_string().contains("file not found"));
    }

    #[test]
    fn test_config_error_io_error_from_conversion() {
        let io_error = IoError::new(ErrorKind::PermissionDenied, "access denied");
        let error: ConfigError = io_error.into();

        match error {
            ConfigError::IoError(ref e) => {
                assert_eq!(e.kind(), ErrorKind::PermissionDenied);
                assert_eq!(e.to_string(), "access denied");
            }
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_config_error_provider_error() {
        let error = ConfigError::ProviderError {
            provider: "env".to_string(),
            message: "variable not set".to_string(),
        };
        assert_eq!(error.to_string(), "provider error: env: variable not set");
    }

    #[test]
    fn test_config_error_provider_error_constructor() {
        let error = ConfigError::provider_error("file", "invalid format");

        match &error {
            ConfigError::ProviderError { provider, message } => {
                assert_eq!(provider, "file");
                assert_eq!(message, "invalid format");
            }
            _ => panic!("Expected ProviderError variant"),
        }

        assert_eq!(error.to_string(), "provider error: file: invalid format");
    }

    #[test]
    fn test_config_error_provider_error_with_display_types() {
        // Test with different Display types
        let error = ConfigError::provider_error(42, true);

        match &error {
            ConfigError::ProviderError { provider, message } => {
                assert_eq!(provider, "42");
                assert_eq!(message, "true");
            }
            _ => panic!("Expected ProviderError variant"),
        }

        assert_eq!(error.to_string(), "provider error: 42: true");
    }

    #[test]
    fn test_config_error_other() {
        let error = ConfigError::Other("custom error message".to_string());
        assert_eq!(error.to_string(), "custom error message");
    }

    #[test]
    fn test_config_error_debug() {
        let error = ConfigError::NotFound;
        let debug_str = format!("{error:?}");
        assert!(debug_str.contains("NotFound"));
    }

    #[test]
    fn test_config_error_debug_with_data() {
        let error = ConfigError::ParseError("test".to_string());
        let debug_str = format!("{error:?}");
        assert!(debug_str.contains("ParseError"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_config_error_is_error_trait() {
        let error = ConfigError::NotFound;
        let _: &dyn std::error::Error = &error;
    }

    #[test]
    fn test_config_error_source() {
        let io_error = IoError::new(ErrorKind::InvalidData, "bad data");
        let error = ConfigError::IoError(io_error);

        assert!(error.source().is_some());
        let source = error.source().unwrap();
        assert_eq!(source.to_string(), "bad data");
    }

    #[test]
    fn test_config_error_no_source() {
        let error = ConfigError::NotFound;
        assert!(error.source().is_none());
    }

    #[test]
    fn test_config_error_variants_equality() {
        // Test that we can match on variants
        let errors = vec![
            ConfigError::NotFound,
            ConfigError::ParseError("test".to_string()),
            ConfigError::Other("other".to_string()),
            ConfigError::ProviderError {
                provider: "test".to_string(),
                message: "msg".to_string(),
            },
        ];

        for error in errors {
            match error {
                ConfigError::NotFound => {}
                ConfigError::ParseError(_) => {}
                ConfigError::IoError(_) => {}
                ConfigError::ProviderError { .. } => {}
                ConfigError::Other(_) => {}
            }
        }
    }

    #[test]
    fn test_config_error_empty_strings() {
        let error = ConfigError::ParseError("".to_string());
        assert_eq!(error.to_string(), "failed to parse configuration: ");

        let error = ConfigError::Other("".to_string());
        assert_eq!(error.to_string(), "");

        let error = ConfigError::ProviderError {
            provider: "".to_string(),
            message: "".to_string(),
        };
        assert_eq!(error.to_string(), "provider error: : ");
    }

    #[test]
    fn test_config_error_special_characters() {
        let error = ConfigError::ParseError("error with\nnewlines\tand\ttabs".to_string());
        assert!(error.to_string().contains("newlines"));
        assert!(error.to_string().contains("tabs"));

        let error = ConfigError::provider_error("provider with spaces", "message with 🚀 emoji");
        assert!(error.to_string().contains("provider with spaces"));
        assert!(error.to_string().contains("🚀"));
    }

    /* File tests */

    #[test]
    fn test_file_format_detection() {
        assert_eq!(
            FileFormat::from_extension(Path::new("config.json")),
            Some(FileFormat::Json)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("config.toml")),
            Some(FileFormat::Toml)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("config.yaml")),
            Some(FileFormat::Yaml)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("config.yml")),
            Some(FileFormat::Yaml)
        );
        assert_eq!(FileFormat::from_extension(Path::new("config.txt")), None);
    }

    #[test]
    fn test_json_config() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.json");

        let content = r#"{
            "server": {
                "host": "127.0.0.1",
                "port": 8080
            },
            "timeout": 30
        }"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        assert!(provider.has("server.host"));
        assert!(!provider.has("server.nonexistent"));

        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "127.0.0.1");

        let port: u16 = provider.get("server.port").unwrap().unwrap();
        assert_eq!(port, 8080);

        let timeout: u32 = provider.get("timeout").unwrap().unwrap();
        assert_eq!(timeout, 30);
    }

    #[test]
    fn test_toml_config() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.toml");

        let content = r#"
            [server]
            host = "127.0.0.1"
            port = 8080

            timeout = 30
        "#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        assert!(provider.has("server.host"));
        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "127.0.0.1");

        let port: u16 = provider.get("server.port").unwrap().unwrap();
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_yaml_config() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.yaml");

        let content = r#"
server:
  host: "127.0.0.1"
  port: 8080
timeout: 30
debug: true
"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        assert!(provider.has("server.host"));
        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "127.0.0.1");

        let port: u16 = provider.get("server.port").unwrap().unwrap();
        assert_eq!(port, 8080);

        let timeout: u32 = provider.get("timeout").unwrap().unwrap();
        assert_eq!(timeout, 30);

        let debug: bool = provider.get("debug").unwrap().unwrap();
        assert!(debug);
    }

    #[test]
    fn test_yml_extension() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.yml");

        let content = r#"
server:
  host: "127.0.0.1"
  port: 8080
"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        assert!(provider.has("server.host"));
        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "127.0.0.1");
    }

    #[test]
    fn test_unsupported_file_format() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.txt");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"some content").unwrap();

        let result = FileConfigProvider::new(file_path.to_str().unwrap());
        assert!(result.is_err());
        if let Err(ConfigError::ProviderError { provider, message }) = result {
            assert_eq!(provider, "file");
            assert!(message.contains("unsupported file format"));
        } else {
            panic!("Expected ProviderError for unsupported file format");
        }
    }

    #[test]
    fn test_nonexistent_file() {
        let result = FileConfigProvider::new("/nonexistent/path/config.json");
        assert!(result.is_err());
        if let Err(ConfigError::ProviderError { provider, message }) = result {
            assert_eq!(provider, "file");
            assert!(message.contains("failed to read file"));
        } else {
            panic!("Expected ProviderError for nonexistent file");
        }
    }

    #[test]
    fn test_invalid_json() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.json");

        let content = r"{ invalid json }";

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let result = FileConfigProvider::new(file_path.to_str().unwrap());
        assert!(result.is_err());
        if let Err(ConfigError::ProviderError { provider, message }) = result {
            assert_eq!(provider, "file");
            assert!(message.contains("invalid JSON"));
        } else {
            panic!("Expected ProviderError for invalid JSON");
        }
    }

    #[test]
    fn test_invalid_toml() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.toml");

        let content = r#"
            [server
            host = "127.0.0.1"
        "#; // Missing closing bracket

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let result = FileConfigProvider::new(file_path.to_str().unwrap());
        assert!(result.is_err());
        if let Err(ConfigError::ProviderError { provider, message }) = result {
            assert_eq!(provider, "file");
            assert!(message.contains("invalid TOML"));
        } else {
            panic!("Expected ProviderError for invalid TOML");
        }
    }

    #[test]
    fn test_invalid_yaml() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.yaml");

        let content = r#"
server:
  host: "127.0.0.1"
  port: 8080
    invalid_indentation: true
"#; // Invalid YAML indentation

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let result = FileConfigProvider::new(file_path.to_str().unwrap());
        assert!(result.is_err());
        if let Err(ConfigError::ProviderError { provider, message }) = result {
            assert_eq!(provider, "file");
            assert!(message.contains("invalid YAML"));
        } else {
            panic!("Expected ProviderError for invalid YAML");
        }
    }

    #[test]
    fn test_complex_nested_structure() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.json");

        let content = r#"{
            "database": {
                "connections": {
                    "primary": {
                        "host": "db1.example.com",
                        "port": 5432,
                        "ssl": true
                    },
                    "secondary": {
                        "host": "db2.example.com",
                        "port": 5433,
                        "ssl": false
                    }
                },
                "pool": {
                    "min_size": 5,
                    "max_size": 20
                }
            },
            "cache": {
                "redis": {
                    "url": "redis://localhost:6379",
                    "timeout": 5000
                }
            }
        }"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        // Test deeply nested values
        assert!(provider.has("database.connections.primary.host"));
        let primary_host: String = provider
            .get("database.connections.primary.host")
            .unwrap()
            .unwrap();
        assert_eq!(primary_host, "db1.example.com");

        let primary_port: u16 = provider
            .get("database.connections.primary.port")
            .unwrap()
            .unwrap();
        assert_eq!(primary_port, 5432);

        let primary_ssl: bool = provider
            .get("database.connections.primary.ssl")
            .unwrap()
            .unwrap();
        assert!(primary_ssl);

        let secondary_ssl: bool = provider
            .get("database.connections.secondary.ssl")
            .unwrap()
            .unwrap();
        assert!(!secondary_ssl);

        let min_pool_size: u32 = provider.get("database.pool.min_size").unwrap().unwrap();
        assert_eq!(min_pool_size, 5);

        let redis_timeout: u32 = provider.get("cache.redis.timeout").unwrap().unwrap();
        assert_eq!(redis_timeout, 5000);

        // Test non-existent nested keys
        assert!(!provider.has("database.connections.tertiary.host"));
        assert!(!provider.has("cache.memcached.url"));
    }

    #[test]
    fn test_array_values() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.json");

        let content = r#"{
            "servers": ["server1", "server2", "server3"],
            "ports": [8080, 8081, 8082],
            "features": {
                "enabled": ["auth", "logging", "metrics"],
                "disabled": ["debug", "profiling"]
            }
        }"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        let servers: Vec<String> = provider.get("servers").unwrap().unwrap();
        assert_eq!(servers, vec!["server1", "server2", "server3"]);

        let ports: Vec<u16> = provider.get("ports").unwrap().unwrap();
        assert_eq!(ports, vec![8080, 8081, 8082]);

        let enabled_features: Vec<String> = provider.get("features.enabled").unwrap().unwrap();
        assert_eq!(enabled_features, vec!["auth", "logging", "metrics"]);
    }

    #[test]
    fn test_empty_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.json");

        let content = r"{}";

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let provider = FileConfigProvider::new(file_path.to_str().unwrap()).unwrap();

        assert!(!provider.has("any.key"));
        let result: Option<String> = provider.get("any.key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_file_format_case_insensitive() {
        assert_eq!(
            FileFormat::from_extension(Path::new("config.JSON")),
            Some(FileFormat::Json)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("config.TOML")),
            Some(FileFormat::Toml)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("config.YAML")),
            Some(FileFormat::Yaml)
        );
        assert_eq!(
            FileFormat::from_extension(Path::new("config.YML")),
            Some(FileFormat::Yaml)
        );
    }

    #[test]
    fn test_file_without_extension() {
        assert_eq!(FileFormat::from_extension(Path::new("config")), None);
        assert_eq!(FileFormat::from_extension(Path::new("config.")), None);
    }

    /* Proxy tests */

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();

        assert_eq!(config.listen, "[::]:8080");
        assert_eq!(config.body_limit, 5 * 1024 * 1024); // 5MB
        assert_eq!(config.header_limit, 256 * 1024); // 256KB
    }

    #[test]
    fn test_server_config_custom() {
        let config = ServerConfig {
            listen: "127.0.0.1:9000".to_string(),
            body_limit: 10 * 1024 * 1024, // 10MB
            header_limit: 512 * 1024,     // 512KB
        };

        assert_eq!(config.listen, "127.0.0.1:9000");
        assert_eq!(config.body_limit, 10 * 1024 * 1024);
        assert_eq!(config.header_limit, 512 * 1024);
    }

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();

        assert_eq!(config.server.listen, "[::]:8080");
        assert_eq!(config.server.body_limit, 5 * 1024 * 1024);
        assert_eq!(config.server.header_limit, 256 * 1024);
        // LoggingConfig default values are tested in the logging module
    }

    #[test]
    fn test_server_config_serialization() {
        let config = ServerConfig::default();

        // Test serialization
        let serialized = serde_json::to_string(&config).expect("Failed to serialize ServerConfig");
        assert!(serialized.contains("\"listen\":\"[::]:8080\""));
        assert!(serialized.contains("\"body_limit\":5242880")); // 5MB in bytes
        assert!(serialized.contains("\"header_limit\":262144")); // 256KB in bytes

        // Test deserialization
        let deserialized: ServerConfig =
            serde_json::from_str(&serialized).expect("Failed to deserialize ServerConfig");
        assert_eq!(deserialized.listen, config.listen);
        assert_eq!(deserialized.body_limit, config.body_limit);
        assert_eq!(deserialized.header_limit, config.header_limit);
    }

    #[test]
    fn test_proxy_config_serialization() {
        let config = ProxyConfig::default();

        // Test serialization
        let serialized = serde_json::to_string(&config).expect("Failed to serialize ProxyConfig");
        assert!(serialized.contains("\"server\""));
        assert!(serialized.contains("\"logging\""));

        // Test deserialization
        let deserialized: ProxyConfig =
            serde_json::from_str(&serialized).expect("Failed to deserialize ProxyConfig");
        assert_eq!(deserialized.server.listen, config.server.listen);
        assert_eq!(deserialized.server.body_limit, config.server.body_limit);
        assert_eq!(deserialized.server.header_limit, config.server.header_limit);
    }

    #[test]
    fn test_server_config_partial_deserialization() {
        // Test that partial JSON can be deserialized with defaults
        let partial_json = r#"{"listen": "0.0.0.0:3000"}"#;
        let config: ServerConfig =
            serde_json::from_str(partial_json).expect("Failed to deserialize partial ServerConfig");

        assert_eq!(config.listen, "0.0.0.0:3000");
        assert_eq!(config.body_limit, 5 * 1024 * 1024); // default
        assert_eq!(config.header_limit, 256 * 1024); // default
    }

    #[test]
    fn test_server_config_full_deserialization() {
        let full_json = r#"{
            "listen": "192.168.1.100:8888",
            "body_limit": 1048576,
            "header_limit": 131072
        }"#;
        let config: ServerConfig =
            serde_json::from_str(full_json).expect("Failed to deserialize full ServerConfig");

        assert_eq!(config.listen, "192.168.1.100:8888");
        assert_eq!(config.body_limit, 1_048_576); // 1MB
        assert_eq!(config.header_limit, 131_072); // 128KB
    }

    #[test]
    fn test_proxy_config_partial_deserialization() {
        let partial_json = r#"{
            "server": {
                "listen": "localhost:4000"
            }
        }"#;
        let config: ProxyConfig =
            serde_json::from_str(partial_json).expect("Failed to deserialize partial ProxyConfig");

        assert_eq!(config.server.listen, "localhost:4000");
        assert_eq!(config.server.body_limit, 5 * 1024 * 1024); // default
        assert_eq!(config.server.header_limit, 256 * 1024); // default
    }

    #[test]
    fn test_server_config_debug() {
        let config = ServerConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("ServerConfig"));
        assert!(debug_str.contains("[::]:8080"));
        assert!(debug_str.contains("5242880")); // 5MB
        assert!(debug_str.contains("262144")); // 256KB
    }

    #[test]
    fn test_proxy_config_debug() {
        let config = ProxyConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("ProxyConfig"));
        assert!(debug_str.contains("server"));
        assert!(debug_str.contains("logging"));
    }

    #[test]
    fn test_server_config_clone() {
        let config = ServerConfig::default();
        let cloned = config.clone();

        assert_eq!(config.listen, cloned.listen);
        assert_eq!(config.body_limit, cloned.body_limit);
        assert_eq!(config.header_limit, cloned.header_limit);
    }

    #[test]
    fn test_proxy_config_clone() {
        let config = ProxyConfig::default();
        let cloned = config.clone();

        assert_eq!(config.server.listen, cloned.server.listen);
        assert_eq!(config.server.body_limit, cloned.server.body_limit);
        assert_eq!(config.server.header_limit, cloned.server.header_limit);
    }

    #[test]
    fn test_server_config_edge_cases() {
        // Test with zero values
        let config = ServerConfig {
            listen: "".to_string(),
            body_limit: 0,
            header_limit: 0,
        };

        assert_eq!(config.listen, "");
        assert_eq!(config.body_limit, 0);
        assert_eq!(config.header_limit, 0);

        // Test serialization/deserialization of edge cases
        let serialized =
            serde_json::to_string(&config).expect("Failed to serialize edge case config");
        let deserialized: ServerConfig =
            serde_json::from_str(&serialized).expect("Failed to deserialize edge case config");

        assert_eq!(deserialized.listen, config.listen);
        assert_eq!(deserialized.body_limit, config.body_limit);
        assert_eq!(deserialized.header_limit, config.header_limit);
    }

    #[test]
    fn test_server_config_large_values() {
        // Test with large values
        let config = ServerConfig {
            listen: "0.0.0.0:65535".to_string(),
            body_limit: usize::MAX,
            header_limit: usize::MAX,
        };

        assert_eq!(config.listen, "0.0.0.0:65535");
        assert_eq!(config.body_limit, usize::MAX);
        assert_eq!(config.header_limit, usize::MAX);
    }

    #[test]
    fn test_invalid_json_deserialization() {
        let invalid_json = r#"{"listen": "localhost:8080", "body_limit": "not_a_number"}"#;
        let result = serde_json::from_str::<ServerConfig>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_json_deserialization() {
        let empty_json = "{}";
        let config: ServerConfig =
            serde_json::from_str(empty_json).expect("Failed to deserialize empty JSON");

        // Should use all defaults
        assert_eq!(config.listen, "[::]:8080");
        assert_eq!(config.body_limit, 5 * 1024 * 1024);
        assert_eq!(config.header_limit, 256 * 1024);
    }

    /* Vault tests */

    #[cfg(feature = "vault-config")]
    mod vault_tests {
        use super::*;
        use std::fs;
        use tempfile::tempdir;

        #[test]
        fn test_vault_basic_interpolation() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            // Create a secret file
            let secret_file = vault_dir.join("redis_password");
            fs::write(&secret_file, "mysecretpassword").unwrap();

            // Create a mock provider with a secret reference
            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "server.secret".to_string(),
                serde_json::json!("${secret.redis_password}"),
            );

            // Wrap with vault provider
            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            // Test interpolation
            let secret: String = vault_provider.get("server.secret").unwrap().unwrap();
            assert_eq!(secret, "mysecretpassword");
        }

        #[test]
        fn test_vault_multiple_secrets_in_string() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            // Create secret files
            fs::write(vault_dir.join("username"), "admin").unwrap();
            fs::write(vault_dir.join("password"), "secret123").unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "database.url".to_string(),
                serde_json::json!(
                    "postgresql://${secret.username}:${secret.password}@localhost:5432/db"
                ),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let url: String = vault_provider.get("database.url").unwrap().unwrap();
            assert_eq!(url, "postgresql://admin:secret123@localhost:5432/db");
        }

        #[test]
        fn test_vault_nested_object_interpolation() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            fs::write(vault_dir.join("db_password"), "dbsecret").unwrap();
            fs::write(vault_dir.join("api_key"), "apikey123").unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "config".to_string(),
                serde_json::json!({
                    "database": {
                        "password": "${secret.db_password}"
                    },
                    "api": {
                        "key": "${secret.api_key}"
                    }
                }),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            #[derive(serde::Deserialize, Debug, PartialEq)]
            struct Config {
                database: DatabaseConfig,
                api: ApiConfig,
            }

            #[derive(serde::Deserialize, Debug, PartialEq)]
            struct DatabaseConfig {
                password: String,
            }

            #[derive(serde::Deserialize, Debug, PartialEq)]
            struct ApiConfig {
                key: String,
            }

            let config: Config = vault_provider.get("config").unwrap().unwrap();
            assert_eq!(config.database.password, "dbsecret");
            assert_eq!(config.api.key, "apikey123");
        }

        #[test]
        fn test_vault_array_interpolation() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            fs::write(vault_dir.join("host1"), "server1.example.com").unwrap();
            fs::write(vault_dir.join("host2"), "server2.example.com").unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "servers".to_string(),
                serde_json::json!(["${secret.host1}", "${secret.host2}", "static.example.com"]),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let servers: Vec<String> = vault_provider.get("servers").unwrap().unwrap();
            assert_eq!(
                servers,
                vec![
                    "server1.example.com",
                    "server2.example.com",
                    "static.example.com"
                ]
            );
        }

        #[test]
        fn test_vault_no_interpolation_needed() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider
                .values
                .insert("server.host".to_string(), serde_json::json!("localhost"));

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let host: String = vault_provider.get("server.host").unwrap().unwrap();
            assert_eq!(host, "localhost");
        }

        #[test]
        fn test_vault_secret_not_found() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "server.secret".to_string(),
                serde_json::json!("${secret.nonexistent}"),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let result = vault_provider.get::<String>("server.secret");
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("secret file not found: nonexistent")
            );
        }

        #[test]
        fn test_vault_invalid_secret_name() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "server.secret".to_string(),
                serde_json::json!("${secret.../etc/passwd}"),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let result = vault_provider.get::<String>("server.secret");
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(error.to_string().contains("invalid secret name"));
        }

        #[test]
        fn test_vault_empty_secret_name() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider
                .values
                .insert("server.secret".to_string(), serde_json::json!("${secret.}"));

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let result = vault_provider.get::<String>("server.secret");
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(error.to_string().contains("empty secret name"));
        }

        #[test]
        fn test_vault_secret_with_whitespace() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            // Create a secret file with whitespace
            let secret_file = vault_dir.join("padded_secret");
            fs::write(&secret_file, "  \n  mysecret  \n  ").unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "server.secret".to_string(),
                serde_json::json!("${secret.padded_secret}"),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let secret: String = vault_provider.get("server.secret").unwrap().unwrap();
            assert_eq!(secret, "mysecret"); // Should be trimmed
        }

        #[test]
        fn test_vault_same_secret_multiple_times() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            fs::write(vault_dir.join("token"), "abc123").unwrap();

            let mut mock_provider = MockConfigProvider::new("test", 0);
            mock_provider.values.insert(
                "auth.header".to_string(),
                serde_json::json!("Bearer ${secret.token} ${secret.token}"),
            );

            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            let header: String = vault_provider.get("auth.header").unwrap().unwrap();
            assert_eq!(header, "Bearer abc123 abc123");
        }

        #[test]
        fn test_vault_provider_name() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            let mock_provider = MockConfigProvider::new("test", 0);
            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            assert_eq!(vault_provider.provider_name(), "vault");
        }

        #[test]
        fn test_vault_has_method() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            let mock_provider = MockConfigProvider::new("test", 0);
            let vault_provider =
                VaultConfigProvider::wrap(mock_provider, vault_dir.to_str().unwrap());

            // Should delegate to inner provider
            assert!(vault_provider.has("server.port"));
            assert!(!vault_provider.has("nonexistent.key"));
        }

        #[test]
        fn test_vault_with_file_provider() {
            let dir = tempdir().unwrap();
            let vault_dir = dir.path().join("vault");
            fs::create_dir_all(&vault_dir).unwrap();

            // Create secret files
            fs::write(vault_dir.join("db_password"), "secretpass").unwrap();

            // Create config file
            let config_file = dir.path().join("config.json");
            let config_content = r#"{
                "database": {
                    "host": "localhost",
                    "password": "${secret.db_password}"
                }
            }"#;
            fs::write(&config_file, config_content).unwrap();

            // Create file provider and wrap with vault
            let file_provider = FileConfigProvider::new(config_file.to_str().unwrap()).unwrap();
            let vault_provider =
                VaultConfigProvider::wrap(file_provider, vault_dir.to_str().unwrap());

            let host: String = vault_provider.get("database.host").unwrap().unwrap();
            assert_eq!(host, "localhost");

            let password: String = vault_provider.get("database.password").unwrap().unwrap();
            assert_eq!(password, "secretpass");
        }

        #[test]
        fn test_vault_default_path() {
            let mock_provider = MockConfigProvider::new("test", 0);
            let vault_provider = VaultConfigProvider::wrap_default(mock_provider);

            // Just test that it creates without error - we can't test actual functionality
            // without creating /vault/secret/ which we shouldn't do in tests
            assert_eq!(vault_provider.provider_name(), "vault");
        }
    }
}
