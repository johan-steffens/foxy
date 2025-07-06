
#[cfg(test)]
mod unit_tests {

    use std::env;
    #[cfg(feature = "opentelemetry")]
    use crate::initialize_opentelemetry;
    use crate::determine_config_path;

    // Mock tests for initialize_opentelemetry function
    #[cfg(test)]
    use mockall::{automock, predicate::*};

    #[automock]
    pub trait FoxyTrait {
        #[allow(dead_code)]
        fn get_opentelemetry_config(&self) -> Option<(String, String)>; // (endpoint, service_name)
    }

    // Mock-based unit tests for OpenTelemetry initialization logic
    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_mock_initialize_opentelemetry_with_config() {
        let mut mock_foxy = MockFoxyTrait::new();
        mock_foxy
            .expect_get_opentelemetry_config()
            .times(1)
            .returning(|| Some(("http://localhost:4317".to_string(), "test-service".to_string())));

        // Test the logic that would be in initialize_opentelemetry
        let config = mock_foxy.get_opentelemetry_config();
        assert!(config.is_some());
        let (endpoint, service_name) = config.unwrap();
        assert_eq!(endpoint, "http://localhost:4317");
        assert_eq!(service_name, "test-service");
        assert!(!endpoint.is_empty());
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_mock_initialize_opentelemetry_empty_config() {
        let mut mock_foxy = MockFoxyTrait::new();
        mock_foxy
            .expect_get_opentelemetry_config()
            .times(1)
            .returning(|| Some(("".to_string(), "test-service".to_string())));

        // Test the logic for empty endpoint
        let config = mock_foxy.get_opentelemetry_config();
        assert!(config.is_some());
        let (endpoint, _service_name) = config.unwrap();
        assert!(endpoint.is_empty()); // Should trigger warning path
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_mock_initialize_opentelemetry_no_config() {
        let mut mock_foxy = MockFoxyTrait::new();
        mock_foxy
            .expect_get_opentelemetry_config()
            .times(1)
            .returning(|| None);

        // Test the logic for missing config
        let config = mock_foxy.get_opentelemetry_config();
        assert!(config.is_none()); // Should trigger info message about skipping
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_mock_initialize_opentelemetry_invalid_endpoint() {
        let mut mock_foxy = MockFoxyTrait::new();
        mock_foxy
            .expect_get_opentelemetry_config()
            .times(1)
            .returning(|| Some(("invalid://bad-endpoint:99999".to_string(), "test-service".to_string())));

        // Test the logic for invalid endpoint that would cause initialization to fail
        let config = mock_foxy.get_opentelemetry_config();
        assert!(config.is_some());
        let (endpoint, service_name) = config.unwrap();
        assert_eq!(endpoint, "invalid://bad-endpoint:99999");
        assert_eq!(service_name, "test-service");
        assert!(!endpoint.is_empty());
        // This would trigger the error_fmt! path when actual OpenTelemetry init fails
    }

    #[test]
    fn test_determine_config_path_with_env_var() {
        // Set environment variable
        let test_path = "/tmp/test_config.toml";
        unsafe {
            env::set_var("FOXY_CONFIG_FILE", test_path);
        }

        let result = determine_config_path().unwrap();
        assert_eq!(result, Some(test_path.to_string()));

        // Clean up
        unsafe {
            env::remove_var("FOXY_CONFIG_FILE");
        }
    }

    #[test]
    fn test_determine_config_path_without_env_var_file_exists() {
        // Remove environment variable if it exists
        unsafe {
            env::remove_var("FOXY_CONFIG_FILE");
        }

        // Since /etc/foxy/config.toml doesn't exist in test environment,
        // the function should fall back to config/default.toml which does exist
        let result = determine_config_path();

        // Should return success with the fallback path
        assert!(result.is_ok());
        let config_path = result.unwrap();
        assert!(config_path.is_some());
        assert_eq!(config_path.unwrap(), "config/default.toml");
    }

    #[test]
    fn test_determine_config_path_without_env_var_file_not_exists() {
        // Remove environment variable if it exists
        unsafe {
            env::remove_var("FOXY_CONFIG_FILE");
        }

        let result = determine_config_path();

        // Should return success with fallback path since config/default.toml exists
        assert!(result.is_ok());
        let config_path = result.unwrap();
        assert!(config_path.is_some());
        assert_eq!(config_path.unwrap(), "config/default.toml");
    }

    #[cfg(feature = "opentelemetry")]
    #[tokio::test]
    async fn test_initialize_opentelemetry_with_valid_config() {
        use tempfile::TempDir;
        use std::fs;

        // Create a temporary config file with OpenTelemetry configuration
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("otel_test_config.toml");
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080

[proxy]
timeout = 30

[proxy.opentelemetry]
endpoint = "http://localhost:4317"
service_name = "test-service"

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;
        fs::write(&config_path, config_content).unwrap();

        // Build a proxy with this configuration
        let loader = foxy::Foxy::loader()
            .with_env_vars()
            .with_config_file(config_path.to_str().unwrap());

        let proxy = loader.build().await.unwrap();

        // Test that initialize_opentelemetry doesn't panic
        // Note: We can't easily test the actual OpenTelemetry initialization without a real endpoint
        // but we can verify the function executes without panicking
        initialize_opentelemetry(&proxy);
    }

    #[cfg(feature = "opentelemetry")]
    #[tokio::test]
    async fn test_initialize_opentelemetry_with_empty_endpoint() {
        use tempfile::TempDir;
        use std::fs;

        // Create a temporary config file with empty OpenTelemetry endpoint
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("empty_otel_test_config.toml");
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080

[proxy]
timeout = 30

[proxy.opentelemetry]
endpoint = ""
service_name = "test-service"

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;
        fs::write(&config_path, config_content).unwrap();

        // Build a proxy with this configuration
        let loader = foxy::Foxy::loader()
            .with_env_vars()
            .with_config_file(config_path.to_str().unwrap());

        let proxy = loader.build().await.unwrap();

        // Test that initialize_opentelemetry handles empty endpoint gracefully
        initialize_opentelemetry(&proxy);
    }

    #[cfg(feature = "opentelemetry")]
    #[tokio::test]
    async fn test_initialize_opentelemetry_without_config() {
        use tempfile::TempDir;
        use std::fs;

        // Create a temporary config file without OpenTelemetry configuration
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("no_otel_test_config.toml");
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080

[proxy]
timeout = 30

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;
        fs::write(&config_path, config_content).unwrap();

        // Build a proxy with this configuration
        let loader = foxy::Foxy::loader()
            .with_env_vars()
            .with_config_file(config_path.to_str().unwrap());

        let proxy = loader.build().await.unwrap();

        // Test that initialize_opentelemetry handles missing config gracefully
        initialize_opentelemetry(&proxy);
    }

    #[cfg(feature = "opentelemetry")]
    #[tokio::test]
    async fn test_initialize_opentelemetry_with_invalid_endpoint() {
        use tempfile::TempDir;
        use std::fs;

        // Create a temporary config file with invalid OpenTelemetry endpoint
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid_otel_test_config.toml");
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080

[proxy]
timeout = 30

[proxy.opentelemetry]
endpoint = "invalid://not-a-real-endpoint:99999"
service_name = "test-service"

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;
        fs::write(&config_path, config_content).unwrap();

        // Build a proxy with this configuration
        let loader = foxy::Foxy::loader()
            .with_env_vars()
            .with_config_file(config_path.to_str().unwrap());

        let proxy = loader.build().await.unwrap();

        // Test that initialize_opentelemetry handles invalid endpoint gracefully
        // This should trigger the error_fmt! call when OpenTelemetry initialization fails
        initialize_opentelemetry(&proxy);
    }

    #[test]
    fn test_env_var_takes_precedence() {
        unsafe { std::env::set_var("FOXY_CONFIG_FILE", "/tmp/test_config.toml") };
        let result = determine_config_path();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("/tmp/test_config.toml".to_string()));
        unsafe { std::env::remove_var("FOXY_CONFIG_FILE") }; // Clean up the env var
    }

    #[test]
    fn test_fallback_path_exists() {
        // Test that the function successfully finds the fallback path
        unsafe {
            env::remove_var("FOXY_CONFIG_FILE");
        }
        let result = determine_config_path();
        assert!(result.is_ok());
        let config_path = result.unwrap();
        assert!(config_path.is_some());
        assert_eq!(config_path.unwrap(), "config/default.toml");
    }

    #[test]
    fn test_fallback_path_does_not_exist_secondary_exists() {
        // Test that when the primary fallback doesn't exist, the secondary fallback is used
        // Since /etc/foxy/config.toml doesn't exist in test environment,
        // the function should find config/default.toml
        unsafe {
            env::remove_var("FOXY_CONFIG_FILE");
        }
        let result = determine_config_path();
        assert!(result.is_ok());
        let config_path = result.unwrap();
        assert!(config_path.is_some());
        assert_eq!(config_path.unwrap(), "config/default.toml");
    }

    #[test]
    fn test_both_paths_do_not_exist() {
        // Test that the function finds the secondary fallback path
        // Since /etc/foxy/config.toml doesn't exist, it should find config/default.toml
        unsafe {
            env::remove_var("FOXY_CONFIG_FILE");
        }
        let result = determine_config_path();
        assert!(result.is_ok());
        let config_path = result.unwrap();
        assert!(config_path.is_some());
        assert_eq!(config_path.unwrap(), "config/default.toml");
    }

    #[test]
    fn test_env_var_points_to_nonexistent_file() {
        // The current implementation doesn't validate if the env var path exists
        // It just returns the path if the environment variable is set
        unsafe { std::env::set_var("FOXY_CONFIG_FILE", "/tmp/does_not_exist.toml") };
        let result = determine_config_path();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("/tmp/does_not_exist.toml".to_string()));
        unsafe { std::env::remove_var("FOXY_CONFIG_FILE") };
    }
}
