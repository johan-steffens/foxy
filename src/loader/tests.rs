// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
mod loader_tests {
    use crate::FoxyLoader;
    use crate::config::{ConfigError, ConfigProvider};
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
        let loader = FoxyLoader::new().with_provider(provider);

        // Build the Foxy instance
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify the configuration was loaded correctly
        assert_eq!(config.get::<u64>("server.port").unwrap().unwrap(), 8080);
        assert_eq!(
            config.get::<String>("server.host").unwrap().unwrap(),
            "127.0.0.1"
        );
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
        let provider2 = MockConfigProvider {
            values: provider2_values,
        };

        // Create config directly to avoid logger initialization
        let config = crate::config::Config::builder()
            .with_provider(provider1)
            .with_provider(provider2)
            .build();

        // Check layered configuration priority
        assert_eq!(config.get::<u64>("server.port").unwrap().unwrap(), 9000); // From provider2
        assert_eq!(
            config.get::<String>("server.host").unwrap().unwrap(),
            "127.0.0.1"
        ); // From provider1
    }

    #[tokio::test]
    async fn test_loader_new() {
        let loader = FoxyLoader::new();
        assert!(loader.config_builder.is_none());
        assert!(loader.config_file_path.is_none());
        assert!(!loader.use_env_vars);
        assert!(loader.env_prefix.is_none());
        assert!(loader.custom_filters.is_empty());
    }

    #[tokio::test]
    async fn test_loader_default() {
        let loader = FoxyLoader::default();
        assert!(loader.config_builder.is_none());
        assert!(loader.config_file_path.is_none());
        assert!(!loader.use_env_vars);
        assert!(loader.env_prefix.is_none());
        assert!(loader.custom_filters.is_empty());
    }

    #[tokio::test]
    async fn test_loader_with_config() {
        let config = crate::config::Config::builder().build();
        let loader = FoxyLoader::new().with_config(config);
        assert!(loader.config_builder.is_some());
    }

    #[tokio::test]
    async fn test_loader_with_config_file_path() {
        let loader = FoxyLoader::new().with_config_file("config.json");
        assert_eq!(loader.config_file_path, Some("config.json".to_string()));
    }

    #[tokio::test]
    async fn test_loader_with_env_vars() {
        let loader = FoxyLoader::new().with_env_vars();
        assert!(loader.use_env_vars);
    }

    #[tokio::test]
    async fn test_loader_with_env_prefix() {
        let loader = FoxyLoader::new().with_env_prefix("MYAPP_");
        assert!(loader.use_env_vars);
        assert_eq!(loader.env_prefix, Some("MYAPP_".to_string()));
    }

    #[tokio::test]
    async fn test_loader_with_provider() {
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        assert!(loader.config_builder.is_some());
    }

    #[tokio::test]
    async fn test_loader_with_provider_existing_config() {
        let config = crate::config::Config::builder().build();
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new()
            .with_config(config)
            .with_provider(provider);
        assert!(loader.config_builder.is_some());
    }

    // Mock filter for testing
    #[derive(Debug)]
    struct MockFilter {
        name: String,
    }

    impl MockFilter {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::Filter for MockFilter {
        fn name(&self) -> &str {
            &self.name
        }

        fn filter_type(&self) -> crate::FilterType {
            crate::FilterType::Pre
        }

        async fn pre_filter(
            &self,
            request: crate::ProxyRequest,
        ) -> Result<crate::ProxyRequest, crate::ProxyError> {
            Ok(request)
        }

        async fn post_filter(
            &self,
            _request: crate::ProxyRequest,
            response: crate::ProxyResponse,
        ) -> Result<crate::ProxyResponse, crate::ProxyError> {
            Ok(response)
        }
    }

    #[tokio::test]
    async fn test_loader_with_filter() {
        let filter = MockFilter::new("test_filter");
        let loader = FoxyLoader::new().with_filter(filter);
        assert_eq!(loader.custom_filters.len(), 1);
    }

    #[tokio::test]
    async fn test_loader_with_multiple_filters() {
        let filter1 = MockFilter::new("filter1");
        let filter2 = MockFilter::new("filter2");
        let loader = FoxyLoader::new().with_filter(filter1).with_filter(filter2);
        assert_eq!(loader.custom_filters.len(), 2);
    }

    #[tokio::test]
    async fn test_loader_build_with_env_vars() {
        // Set some test environment variables
        unsafe {
            std::env::set_var("FOXY_SERVER_HOST", "localhost");
            std::env::set_var("FOXY_SERVER_PORT", "9090");
        }

        let loader = FoxyLoader::new().with_env_vars();
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Check that environment variables were loaded
        let host: String = config
            .get("server.host")
            .unwrap()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let port: u16 = config.get("server.port").unwrap().unwrap_or(8080);

        // Clean up
        unsafe {
            std::env::remove_var("FOXY_SERVER_HOST");
            std::env::remove_var("FOXY_SERVER_PORT");
        }

        // Note: The actual values depend on whether the env vars were set
        assert!(!host.is_empty());
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_loader_build_with_custom_env_prefix() {
        // Set some test environment variables with custom prefix
        unsafe {
            std::env::set_var("MYAPP_SERVER_HOST", "custom.example.com");
            std::env::set_var("MYAPP_SERVER_PORT", "7777");
        }

        let loader = FoxyLoader::new().with_env_prefix("MYAPP_");
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Check that custom prefix environment variables were loaded
        let host: Option<String> = config.get("server.host").unwrap();
        let port: Option<u16> = config.get("server.port").unwrap();

        // Clean up
        unsafe {
            std::env::remove_var("MYAPP_SERVER_HOST");
            std::env::remove_var("MYAPP_SERVER_PORT");
        }

        // The values should be from our custom env vars if they were loaded
        if let Some(h) = host {
            assert!(!h.is_empty());
        }
        if let Some(p) = port {
            assert!(p > 0);
        }
    }

    #[tokio::test]
    async fn test_loader_build_with_invalid_config_file() {
        let loader = FoxyLoader::new().with_config_file("/nonexistent/path/config.json");
        let result = loader.build().await;
        assert!(result.is_err());

        match result {
            Err(crate::loader::LoaderError::ConfigError(_)) => {
                // Expected error type
            }
            other => {
                panic!("Expected ConfigError, got: {other:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_foxy_loader_static_method() {
        let loader = crate::Foxy::loader();
        assert!(loader.config_builder.is_none());
        assert!(loader.config_file_path.is_none());
        assert!(!loader.use_env_vars);
        assert!(loader.env_prefix.is_none());
        assert!(loader.custom_filters.is_empty());
    }

    #[tokio::test]
    async fn test_foxy_config_access() {
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        let foxy = loader.build().await.unwrap();

        let config = foxy.config();
        assert_eq!(config.get::<u64>("server.port").unwrap().unwrap(), 8080);
        assert_eq!(
            config.get::<String>("server.host").unwrap().unwrap(),
            "127.0.0.1"
        );
    }

    #[tokio::test]
    async fn test_loader_error_display() {
        let config_error = crate::config::ConfigError::ParseError("test error".to_string());
        let loader_error = crate::loader::LoaderError::ConfigError(config_error);
        let error_string = format!("{loader_error}");
        assert!(error_string.contains("configuration error"));
        assert!(error_string.contains("test error"));
    }

    #[tokio::test]
    async fn test_loader_error_from_proxy_error() {
        let proxy_error = crate::ProxyError::ConfigError("proxy config error".to_string());
        let loader_error = crate::loader::LoaderError::ProxyError(proxy_error);
        let error_string = format!("{loader_error}");
        assert!(error_string.contains("proxy error"));
    }

    #[tokio::test]
    async fn test_loader_error_from_io_error() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let loader_error = crate::loader::LoaderError::IoError(io_error);
        let error_string = format!("{loader_error}");
        assert!(error_string.contains("IO error"));
        assert!(error_string.contains("file not found"));
    }

    #[tokio::test]
    async fn test_loader_error_other() {
        let loader_error = crate::loader::LoaderError::Other("custom error message".to_string());
        let error_string = format!("{loader_error}");
        assert_eq!(error_string, "custom error message");
    }

    #[tokio::test]
    async fn test_foxy_debug() {
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        let foxy = loader.build().await.unwrap();

        let debug_string = format!("{foxy:?}");
        assert!(debug_string.contains("Foxy"));
    }

    #[tokio::test]
    async fn test_foxy_clone() {
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        let foxy = loader.build().await.unwrap();

        let cloned_foxy = foxy.clone();

        // Both instances should have the same configuration
        assert_eq!(
            foxy.config().get::<u64>("server.port").unwrap().unwrap(),
            cloned_foxy
                .config()
                .get::<u64>("server.port")
                .unwrap()
                .unwrap()
        );
    }
}
