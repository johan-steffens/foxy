// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::config::{Config, ConfigProvider, ConfigError};
    use serde_json::Value;

    // Simple mock config provider for testing
    #[derive(Debug)]
    struct MockConfigProvider {
        values: serde_json::Map<String, Value>,
        name: String,
        priority: usize,
    }

    impl MockConfigProvider {
        fn new(name: &str, priority: usize) -> Self {
            let mut values = serde_json::Map::new();
            values.insert("server.port".to_string(), serde_json::json!(8080));
            values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));
            Self { values, name: name.to_string(), priority }
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
        provider2.values.insert("server.port".to_string(), serde_json::json!(9000));
        
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
        let config = Config::builder()
            .with_provider(provider)
            .build();
        
        // Existing value
        let port = config.get_or_default("server.port", 1234).unwrap();
        assert_eq!(port, 8080);
        
        // Default value for non-existent key
        let timeout = config.get_or_default("server.timeout", 30).unwrap();
        assert_eq!(timeout, 30);
    }
}
