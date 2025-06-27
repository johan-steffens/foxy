// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! File-based configuration provider implementation.

use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use toml;

use super::ConfigError;
use super::ConfigProvider;

/// Supported file formats for configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// JSON format (.json)
    Json,
    /// TOML format (.toml)
    Toml,
    /// YAML format (.yaml, .yml)
    Yaml,
}

impl FileFormat {
    /// Detect the file format from the file extension.
    pub fn from_extension(path: &Path) -> Option<Self> {
        path.extension().and_then(|ext| {
            let ext_str = ext.to_string_lossy().to_lowercase();
            match ext_str.as_str() {
                "json" => Some(FileFormat::Json),
                "toml" => Some(FileFormat::Toml),
                "yaml" | "yml" => Some(FileFormat::Yaml),
                _ => None,
            }
        })
    }
}

/// File-based configuration provider.
#[derive(Debug)]
pub struct FileConfigProvider {
    #[allow(dead_code)]
    path: PathBuf,
    #[allow(dead_code)]
    format: FileFormat,
    data: HashMap<String, serde_json::Value>,
}

impl FileConfigProvider {
    /// Create a new file-based configuration provider.
    pub fn new(path: &str) -> Result<Self, ConfigError> {
        let path_buf = PathBuf::from(path);
        let format = FileFormat::from_extension(&path_buf)
            .ok_or_else(|| ConfigError::provider_error("file", "unsupported file format"))?;

        let data = Self::read_file(&path_buf, format)?;

        Ok(Self {
            path: path_buf,
            format,
            data,
        })
    }

    /// Read and parse a configuration file.
    fn read_file(
        path: &Path,
        format: FileFormat,
    ) -> Result<HashMap<String, serde_json::Value>, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| {
            ConfigError::provider_error("file", format!("failed to read file: {e}"))
        })?;

        match format {
            FileFormat::Json => serde_json::from_str(&content)
                .map_err(|e| ConfigError::provider_error("file", format!("invalid JSON: {e}"))),
            FileFormat::Toml => {
                let toml_value: toml::Value = toml::from_str(&content).map_err(|e| {
                    ConfigError::provider_error("file", format!("invalid TOML: {e}"))
                })?;

                // Convert toml::Value to serde_json::Value for unified internal representation
                let json_value = serde_json::to_value(toml_value).map_err(|e| {
                    ConfigError::provider_error("file", format!("failed to convert TOML: {e}"))
                })?;

                match json_value {
                    serde_json::Value::Object(map) => {
                        // Convert the map to our format
                        Ok(map.into_iter().collect())
                    }
                    _ => Err(ConfigError::provider_error(
                        "file",
                        "root configuration must be an object",
                    )),
                }
            }
            FileFormat::Yaml => {
                let yaml_value: serde_yaml::Value =
                    serde_yaml::from_str(&content).map_err(|e| {
                        ConfigError::provider_error("file", format!("invalid YAML: {e}"))
                    })?;

                let json_value = serde_json::to_value(yaml_value).map_err(|e| {
                    ConfigError::provider_error("file", format!("failed to convert YAML: {e}"))
                })?;

                match json_value {
                    serde_json::Value::Object(map) => Ok(map.into_iter().collect()),
                    _ => Err(ConfigError::provider_error(
                        "file",
                        "root configuration must be an object",
                    )),
                }
            }
        }
    }

    /// Get a nested value from the configuration by a dot-separated key path.
    fn get_nested_value(&self, key_path: &str) -> Option<&serde_json::Value> {
        let parts: Vec<&str> = key_path.split('.').collect();

        let mut current = self.data.get(parts[0])?;

        for part in parts.iter().skip(1) {
            current = current.get(part)?;
        }

        Some(current)
    }
}

impl ConfigProvider for FileConfigProvider {
    fn has(&self, key: &str) -> bool {
        self.get_nested_value(key).is_some()
    }

    fn provider_name(&self) -> &str {
        "file"
    }

    fn get_raw(&self, key: &str) -> Result<Option<serde_json::Value>, ConfigError> {
        match self.get_nested_value(key) {
            Some(value) => Ok(Some(value.clone())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigProviderExt;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

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

        let content = r#"{ invalid json }"#;

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

        let content = r#"{}"#;

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
}
