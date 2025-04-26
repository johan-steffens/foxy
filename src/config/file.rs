// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! File-based configuration provider implementation.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use serde_json;
use toml;

use super::ConfigProvider;
use super::ConfigError;

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
    path: PathBuf,
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
    fn read_file(path: &Path, format: FileFormat) -> Result<HashMap<String, serde_json::Value>, ConfigError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::provider_error("file", format!("failed to read file: {}", e)))?;

        match format {
            FileFormat::Json => {
                serde_json::from_str(&content)
                    .map_err(|e| ConfigError::provider_error("file", format!("invalid JSON: {}", e)))
            },
            FileFormat::Toml => {
                let toml_value: toml::Value = toml::from_str(&content)
                    .map_err(|e| ConfigError::provider_error("file", format!("invalid TOML: {}", e)))?;

                // Convert toml::Value to serde_json::Value for unified internal representation
                let json_value = serde_json::to_value(toml_value)
                    .map_err(|e| ConfigError::provider_error("file", format!("failed to convert TOML: {}", e)))?;

                match json_value {
                    serde_json::Value::Object(map) => {
                        // Convert the map to our format
                        Ok(map.into_iter().collect())
                    },
                    _ => Err(ConfigError::provider_error("file", "root configuration must be an object")),
                }
            },
            FileFormat::Yaml => {
                #[cfg(feature = "yaml")]
                {
                    let yaml_value: serde_yaml::Value = serde_yaml::from_str(&content)
                        .map_err(|e| ConfigError::provider_error("file", format!("invalid YAML: {}", e)))?;

                    let json_value = serde_json::to_value(yaml_value)
                        .map_err(|e| ConfigError::provider_error("file", format!("failed to convert YAML: {}", e)))?;

                    match json_value {
                        serde_json::Value::Object(map) => {
                            Ok(map.into_iter().collect())
                        },
                        _ => Err(ConfigError::provider_error("file", "root configuration must be an object")),
                    }
                }

                #[cfg(not(feature = "yaml"))]
                {
                    Err(ConfigError::provider_error("file", "YAML support is not enabled"))
                }
            },
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
    fn get_raw(&self, key: &str) -> Result<Option<serde_json::Value>, ConfigError> {
        match self.get_nested_value(key) {
            Some(value) => Ok(Some(value.clone())),
            None => Ok(None),
        }
    }

    fn has(&self, key: &str) -> bool {
        self.get_nested_value(key).is_some()
    }

    fn provider_name(&self) -> &str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use crate::config::ConfigProviderExt;

    #[test]
    fn test_file_format_detection() {
        assert_eq!(FileFormat::from_extension(Path::new("config.json")), Some(FileFormat::Json));
        assert_eq!(FileFormat::from_extension(Path::new("config.toml")), Some(FileFormat::Toml));
        assert_eq!(FileFormat::from_extension(Path::new("config.yaml")), Some(FileFormat::Yaml));
        assert_eq!(FileFormat::from_extension(Path::new("config.yml")), Some(FileFormat::Yaml));
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

        assert_eq!(provider.has("server.host"), true);
        assert_eq!(provider.has("server.nonexistent"), false);

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

        assert_eq!(provider.has("server.host"), true);
        let host: String = provider.get("server.host").unwrap().unwrap();
        assert_eq!(host, "127.0.0.1");

        let port: u16 = provider.get("server.port").unwrap().unwrap();
        assert_eq!(port, 8080);
    }
}