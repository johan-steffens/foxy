// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod config_tests {
    use crate::config::{Config, ConfigBuilder, ConfigError, ConfigProvider, ConfigProviderExt};
    use serde_json::Value;

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
        let debug_str = format!("{:?}", provider);
        assert!(debug_str.contains("MockConfigProvider"));
        assert!(debug_str.contains("test-provider"));
    }

    #[test]
    fn test_config_builder_debug() {
        let provider = MockConfigProvider::new("test", 0);
        let builder = ConfigBuilder::new().with_provider(provider);
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("ConfigBuilder"));
    }

    #[test]
    fn test_config_debug() {
        let provider = MockConfigProvider::new("test", 0);
        let config = Config::builder().with_provider(provider).build();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
    }
}
