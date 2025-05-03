// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod tests {
    use crate::FoxyLoader;
    use crate::config::{ConfigProvider, ConfigError};
    use serde_json::Value;
    use std::collections::HashMap;

    // Mock config provider for testing
    #[derive(Debug)]
    struct MockConfigProvider {
        values: HashMap<String, Value>,
    }

    impl MockConfigProvider {
        fn new() -> Self {
            let mut values = HashMap::new();
            values.insert("server.port".to_string(), serde_json::json!(8080));
            values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));
            Self { values }
        }
    }

    impl ConfigProvider for MockConfigProvider {
        fn has(&self, key: &str) -> bool {
            self.values.contains_key(key)
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
            Ok(self.values.get(key).cloned())
        }
    }

    #[tokio::test]
    async fn test_loader_with_config_file() {
        // Skip logger initialization to avoid conflicts with other tests
        let provider = MockConfigProvider::new();
        
        // Create a loader with our mock provider
        let loader = FoxyLoader::new()
            .with_provider(provider);
        
        // Build the Foxy instance
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();
        
        // Verify the configuration was loaded correctly
        assert_eq!(config.get::<u64>("server.port").unwrap().unwrap(), 8080);
        assert_eq!(config.get::<String>("server.host").unwrap().unwrap(), "127.0.0.1");
    }

    #[tokio::test]
    async fn test_loader_with_layered_config() {
        // Skip logger initialization to avoid conflicts with other tests
        // by directly creating the Config object instead of using the loader's build method
        
        // Create first provider with default values
        let provider1 = MockConfigProvider::new();
        
        // Create second provider with overridden port
        let mut provider2_values = HashMap::new();
        provider2_values.insert("server.port".to_string(), serde_json::json!(9000));
        let provider2 = MockConfigProvider { values: provider2_values };
        
        // Create config directly to avoid logger initialization
        let config = crate::config::Config::builder()
            .with_provider(provider1)
            .with_provider(provider2)
            .build();
        
        // Check layered configuration priority
        assert_eq!(config.get::<u64>("server.port").unwrap().unwrap(), 9000); // From provider2
        assert_eq!(config.get::<String>("server.host").unwrap().unwrap(), "127.0.0.1"); // From provider1
    }
}
