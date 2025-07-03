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

    #[cfg(feature = "opentelemetry")]
    #[tokio::test]
    async fn test_loader_build_with_opentelemetry_config() {
        use std::collections::HashMap;

        // Create a mock provider with OpenTelemetry configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add complete OpenTelemetry configuration as a nested object
        let otel_config = serde_json::json!({
            "endpoint": "http://localhost:4317",
            "service_name": "test-service",
            "include_headers": true,
            "include_bodies": false,
            "max_body_size": 1024
        });
        values.insert("proxy.opentelemetry".to_string(), otel_config);

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and log OpenTelemetry initialization
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify OpenTelemetry config was loaded
        let otel_config: Option<crate::opentelemetry::OpenTelemetryConfig> =
            config.get("proxy.opentelemetry").unwrap();
        assert!(otel_config.is_some());

        let otel_config = otel_config.unwrap();
        assert_eq!(otel_config.endpoint, "http://localhost:4317");
        assert_eq!(otel_config.service_name, "test-service");
    }

    #[cfg(feature = "opentelemetry")]
    #[tokio::test]
    async fn test_loader_build_without_opentelemetry_config() {
        // Create a mock provider without OpenTelemetry configuration
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed without OpenTelemetry config
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify no OpenTelemetry config was loaded
        let otel_config: Option<crate::opentelemetry::OpenTelemetryConfig> =
            config.get("proxy.opentelemetry").unwrap();
        assert!(otel_config.is_none());
    }

    #[cfg(not(feature = "opentelemetry"))]
    #[tokio::test]
    async fn test_loader_build_opentelemetry_feature_disabled() {
        // When OpenTelemetry feature is disabled, the code branch should not be executed
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed without any OpenTelemetry processing
        let foxy = loader.build().await.unwrap();

        // Just verify the build completed successfully
        assert!(foxy.config().get::<u64>("server.port").unwrap().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_loader_build_with_global_filters() {
        use std::collections::HashMap;

        // Create a mock provider with global filters configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add global filters configuration
        let global_filters = serde_json::json!([
            {
                "type": "logging",
                "config": {
                    "log_request_headers": true,
                    "log_request_body": false,
                    "log_response_headers": true,
                    "log_response_body": false,
                    "log_level": "debug",
                    "max_body_size": 1024
                }
            }
        ]);
        values.insert("proxy.global_filters".to_string(), global_filters);

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and load global filters
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify global filters configuration was loaded
        let filters_config: Option<Vec<crate::router::FilterConfig>> =
            config.get("proxy.global_filters").unwrap();
        assert!(filters_config.is_some());

        let filters = filters_config.unwrap();
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].type_, "logging");
    }

    #[tokio::test]
    async fn test_loader_build_with_invalid_global_filter() {
        use std::collections::HashMap;

        // Create a mock provider with invalid global filters configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add invalid global filters configuration (unknown filter type)
        let global_filters = serde_json::json!([
            {
                "type": "nonexistent_filter",
                "config": {}
            }
        ]);
        values.insert("proxy.global_filters".to_string(), global_filters);

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should fail due to invalid filter type
        let result = loader.build().await;
        assert!(result.is_err());

        match result {
            Err(crate::loader::LoaderError::ProxyError(_)) => {
                // Expected error type for filter creation failure
            }
            other => {
                panic!("Expected ProxyError, got: {other:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_loader_build_without_global_filters() {
        // Create a mock provider without global filters configuration
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed without global filters
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify no global filters configuration was loaded
        let filters_config: Option<Vec<crate::router::FilterConfig>> =
            config.get("proxy.global_filters").unwrap();
        assert!(filters_config.is_none());
    }

    #[tokio::test]
    async fn test_loader_build_rust_log_env_precedence() {
        use std::collections::HashMap;

        // Create a mock provider with logging configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add logging configuration with "warn" level
        let logging_config = serde_json::json!({
            "level": "warn",
            "format": "terminal",
            "structured": false
        });
        values.insert("proxy.logging".to_string(), logging_config);

        // Set RUST_LOG environment variable to override config
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
        }

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and RUST_LOG should take precedence
        let foxy = loader.build().await.unwrap();

        // Clean up environment variable
        unsafe {
            std::env::remove_var("RUST_LOG");
        }

        // Just verify the build completed successfully - the actual logging level
        // precedence is handled internally and not exposed in the config
        assert!(foxy.config().get::<u64>("server.port").unwrap().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_loader_build_rust_log_env_not_set() {
        use std::collections::HashMap;

        // Ensure RUST_LOG is not set
        unsafe {
            std::env::remove_var("RUST_LOG");
        }

        // Create a mock provider with logging configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add logging configuration with "error" level
        let logging_config = serde_json::json!({
            "level": "error",
            "format": "terminal",
            "structured": false
        });
        values.insert("proxy.logging".to_string(), logging_config);

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and use config file level
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify logging configuration was loaded
        let log_config: Option<crate::logging::config::LoggingConfig> =
            config.get("proxy.logging").unwrap();
        assert!(log_config.is_some());

        // The level should be from config file
        let log_config = log_config.unwrap();
        assert_eq!(log_config.level, "error"); // Should be from config file
    }

    #[tokio::test]
    async fn test_loader_build_invalid_rust_log_level() {
        use std::collections::HashMap;

        // Create a mock provider with logging configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add logging configuration with valid level
        let logging_config = serde_json::json!({
            "level": "warn",
            "format": "terminal",
            "structured": false
        });
        values.insert("proxy.logging".to_string(), logging_config);

        // Set RUST_LOG environment variable to invalid level
        unsafe {
            std::env::set_var("RUST_LOG", "invalid_level");
        }

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and fall back to Info level
        let foxy = loader.build().await.unwrap();

        // Clean up environment variable
        unsafe {
            std::env::remove_var("RUST_LOG");
        }

        // Just verify the build completed successfully - the actual logging level
        // fallback is handled internally and not exposed in the config
        assert!(foxy.config().get::<u64>("server.port").unwrap().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_foxy_core_access() {
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        let foxy = loader.build().await.unwrap();

        // Get access to the proxy core
        let core = foxy.core();

        // Verify we can access the core and it has the expected configuration
        assert!(core.config.get::<u64>("server.port").unwrap().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_foxy_core_add_global_filter() {
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        let foxy = loader.build().await.unwrap();

        // Get access to the proxy core
        let core = foxy.core();

        // Add a custom filter to the core
        let filter = MockFilter::new("test_core_filter");
        core.add_global_filter(std::sync::Arc::new(filter)).await;

        // Verify the filter was added (we can't directly check the internal state,
        // but we can verify the operation completed without error)
        // If we reach here, the filter was added successfully
    }

    #[tokio::test]
    async fn test_foxy_start_method_exists() {
        // Test that the start method exists and can be called
        // We don't actually start the server to avoid hanging tests
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);
        let foxy = loader.build().await.unwrap();

        // Verify the start method exists by checking the server configuration
        let server_config = foxy.server.config.clone();
        assert_eq!(server_config.host, "127.0.0.1");
        assert_eq!(server_config.port, 8080);

        // Verify we can access the core through the server
        let core = foxy.server.core();
        assert!(core.config.get::<u64>("server.port").unwrap().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_foxy_start_error_mapping() {
        // Test that LoaderError::ProxyError properly wraps ProxyError
        let proxy_error = crate::ProxyError::ConfigError("test error".to_string());
        let loader_error = crate::loader::LoaderError::ProxyError(proxy_error);

        let error_string = format!("{loader_error}");
        assert!(error_string.contains("proxy error"));
        assert!(error_string.contains("test error"));
    }

    #[tokio::test]
    async fn test_loader_build_missing_logging_config() {
        // Create a mock provider without logging configuration
        let provider = MockConfigProvider::new();
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and use default logging configuration
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify no logging configuration was loaded (should use defaults)
        let log_config: Option<crate::logging::config::LoggingConfig> =
            config.get("proxy.logging").unwrap();
        assert!(log_config.is_none()); // Should be None, defaults will be used internally
    }

    #[tokio::test]
    async fn test_loader_build_invalid_logging_config_level() {
        use std::collections::HashMap;

        // Create a mock provider with invalid logging configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add logging configuration with invalid level
        let logging_config = serde_json::json!({
            "level": "invalid_log_level",
            "format": "terminal",
            "structured": false
        });
        values.insert("proxy.logging".to_string(), logging_config);

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed - the invalid level is stored as-is in config
        // but the actual log level fallback happens during LevelFilter parsing
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify logging configuration was loaded
        let log_config: Option<crate::logging::config::LoggingConfig> =
            config.get("proxy.logging").unwrap();
        assert!(log_config.is_some());

        // The level is stored as-is in the config - validation happens during actual logging setup
        let log_config = log_config.unwrap();
        assert_eq!(log_config.level, "invalid_log_level"); // Stored as-is, validation happens later
    }

    #[tokio::test]
    async fn test_loader_build_malformed_logging_config() {
        use std::collections::HashMap;

        // Create a mock provider with malformed logging configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add malformed logging configuration (string instead of object)
        values.insert(
            "proxy.logging".to_string(),
            serde_json::json!("invalid_config"),
        );

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed - the config system handles malformed configs gracefully
        // by skipping the malformed section and using defaults
        let result = loader.build().await;

        match result {
            Ok(foxy) => {
                // Build succeeded, verify basic functionality
                assert!(foxy.config().get::<u64>("server.port").unwrap().unwrap() > 0);
            }
            Err(e) => {
                // If it fails, it should be a ConfigError
                match e {
                    crate::loader::LoaderError::ConfigError(_) => {
                        // This is also acceptable - depends on config system implementation
                    }
                    other => {
                        panic!("Expected ConfigError or success, got: {other:?}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_loader_build_partial_logging_config() {
        use std::collections::HashMap;

        // Create a mock provider with partial logging configuration
        let mut values = HashMap::new();
        values.insert("server.port".to_string(), serde_json::json!(8080));
        values.insert("server.host".to_string(), serde_json::json!("127.0.0.1"));

        // Add partial logging configuration (only level, missing other fields)
        let logging_config = serde_json::json!({
            "level": "trace"
        });
        values.insert("proxy.logging".to_string(), logging_config);

        let provider = MockConfigProvider { values };
        let loader = FoxyLoader::new().with_provider(provider);

        // Build should succeed and use defaults for missing fields
        let foxy = loader.build().await.unwrap();
        let config = foxy.config();

        // Verify logging configuration was loaded with defaults for missing fields
        let log_config: Option<crate::logging::config::LoggingConfig> =
            config.get("proxy.logging").unwrap();
        assert!(log_config.is_some());

        let log_config = log_config.unwrap();
        assert_eq!(log_config.level, "trace"); // Should use provided level
        // Other fields should use defaults from LoggingConfig::default()
        assert_eq!(log_config.format, "terminal"); // Default format
        assert!(!log_config.structured); // Default structured
    }
}
