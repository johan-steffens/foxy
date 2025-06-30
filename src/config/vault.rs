// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Vault-based configuration provider implementation.
//!
//! This module provides a configuration provider that can interpolate secrets
//! from the filesystem into configuration values. It wraps another ConfigProvider
//! and performs secret interpolation on the values returned by the wrapped provider.
//!
//! # Secret Interpolation
//!
//! The provider looks for patterns like `${secret.name}` in string values and
//! replaces them with the contents of files from the vault directory.
//!
//! For example, if you have a configuration value:
//! ```json
//! {
//!   "database": {
//!     "password": "${secret.db_password}"
//!   }
//! }
//! ```
//!
//! And a file `/vault/secret/db_password` containing `mysecretpassword`,
//! the provider will return:
//! ```json
//! {
//!   "database": {
//!     "password": "mysecretpassword"
//!   }
//! }
//! ```
//!
//! # Security
//!
//! - Secret names are validated to prevent path traversal attacks
//! - Secret files are limited to 1MB in size
//! - Only files within the configured vault directory can be accessed
//! - No recursive secret interpolation is performed

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use super::{ConfigError, ConfigProvider};

/// Maximum size for secret files (1MB)
const MAX_SECRET_SIZE: u64 = 1024 * 1024;

/// Maximum length for secret names
const MAX_SECRET_NAME_LENGTH: usize = 255;

/// Regex pattern for matching secret interpolation syntax
static SECRET_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$\{secret\.([^}]*)\}").expect("Invalid regex pattern")
});

/// Configuration provider that interpolates secrets from the filesystem.
///
/// This provider wraps another ConfigProvider and performs secret interpolation
/// on the values returned by the wrapped provider. It looks for patterns like
/// `${secret.name}` in string values and replaces them with the contents of
/// files from the vault directory.
#[derive(Debug)]
pub struct VaultConfigProvider {
    /// The wrapped configuration provider
    inner: Arc<dyn ConfigProvider>,
    /// Path to the vault directory containing secret files
    vault_path: PathBuf,
}

impl VaultConfigProvider {
    /// Create a new VaultConfigProvider that wraps another provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The configuration provider to wrap
    /// * `vault_path` - Path to the directory containing secret files
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use foxy::config::{FileConfigProvider, VaultConfigProvider};
    ///
    /// let file_provider = FileConfigProvider::new("config.json")?;
    /// let vault_provider = VaultConfigProvider::wrap(file_provider, "/vault/secret");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn wrap<P: ConfigProvider + 'static>(provider: P, vault_path: &str) -> Self {
        Self {
            inner: Arc::new(provider),
            vault_path: PathBuf::from(vault_path),
        }
    }

    /// Create a new VaultConfigProvider with the default vault path.
    ///
    /// The default vault path is `/vault/secret/`.
    ///
    /// # Arguments
    ///
    /// * `provider` - The configuration provider to wrap
    pub fn wrap_default<P: ConfigProvider + 'static>(provider: P) -> Self {
        Self::wrap(provider, "/vault/secret")
    }

    /// Interpolate secrets in a JSON value.
    ///
    /// This method recursively processes JSON values, looking for string values
    /// that contain secret interpolation patterns and replacing them with the
    /// contents of the corresponding secret files.
    fn interpolate_secrets(&self, value: Value) -> Result<Value, ConfigError> {
        match value {
            Value::String(s) => self.interpolate_string(&s).map(Value::String),
            Value::Object(mut obj) => {
                for (_key, val) in obj.iter_mut() {
                    *val = self.interpolate_secrets(val.clone())?;
                }
                Ok(Value::Object(obj))
            }
            Value::Array(mut arr) => {
                for val in arr.iter_mut() {
                    *val = self.interpolate_secrets(val.clone())?;
                }
                Ok(Value::Array(arr))
            }
            // Numbers, booleans, and null values pass through unchanged
            other => Ok(other),
        }
    }

    /// Interpolate secrets in a string value.
    ///
    /// This method looks for patterns like `${secret.name}` in the string and
    /// replaces them with the contents of the corresponding secret files.
    fn interpolate_string(&self, s: &str) -> Result<String, ConfigError> {
        let mut result = s.to_string();
        let mut secrets_cache: HashMap<String, String> = HashMap::new();

        // Find all secret patterns in the string
        for captures in SECRET_PATTERN.captures_iter(s) {
            let full_match = captures.get(0).unwrap().as_str();
            let secret_name = captures.get(1).unwrap().as_str();

            // Get the secret value (with caching to avoid reading the same file multiple times)
            let secret_value = if let Some(cached_value) = secrets_cache.get(secret_name) {
                cached_value.clone()
            } else {
                let value = self.read_secret(secret_name)?;
                secrets_cache.insert(secret_name.to_string(), value.clone());
                value
            };

            // Replace the pattern with the secret value
            result = result.replace(full_match, &secret_value);
        }

        Ok(result)
    }

    /// Read a secret from the vault directory.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the secret to read
    ///
    /// # Returns
    ///
    /// The contents of the secret file, with leading and trailing whitespace trimmed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret name is invalid (contains path traversal characters)
    /// - The secret file doesn't exist
    /// - The secret file is too large
    /// - There's an I/O error reading the file
    fn read_secret(&self, name: &str) -> Result<String, ConfigError> {
        // Validate the secret name
        self.validate_secret_name(name)?;

        // Construct the path to the secret file
        let secret_path = self.vault_path.join(name);

        // Check if the file exists
        if !secret_path.exists() {
            return Err(ConfigError::provider_error(
                "vault",
                format!("secret file not found: {}", name),
            ));
        }

        // Check file size
        let metadata = fs::metadata(&secret_path).map_err(|e| {
            ConfigError::provider_error(
                "vault",
                format!("failed to read secret metadata '{}': {}", name, e),
            )
        })?;

        if metadata.len() > MAX_SECRET_SIZE {
            return Err(ConfigError::provider_error(
                "vault",
                format!("secret file too large: {} (max: {} bytes)", name, MAX_SECRET_SIZE),
            ));
        }

        // Read the file contents
        let content = fs::read_to_string(&secret_path).map_err(|e| {
            ConfigError::provider_error(
                "vault",
                format!("failed to read secret '{}': {}", name, e),
            )
        })?;

        // Return the trimmed content
        Ok(content.trim().to_string())
    }

    /// Validate a secret name to prevent security issues.
    ///
    /// # Arguments
    ///
    /// * `name` - The secret name to validate
    ///
    /// # Errors
    ///
    /// Returns an error if the secret name:
    /// - Is empty
    /// - Is too long
    /// - Contains path traversal characters (`.`, `/`, `\`)
    fn validate_secret_name(&self, name: &str) -> Result<(), ConfigError> {
        if name.is_empty() {
            return Err(ConfigError::provider_error("vault", "empty secret name"));
        }

        if name.len() > MAX_SECRET_NAME_LENGTH {
            return Err(ConfigError::provider_error(
                "vault",
                format!("secret name too long: {} (max: {} characters)", name, MAX_SECRET_NAME_LENGTH),
            ));
        }

        if name.contains("..") || name.contains('/') || name.contains('\\') {
            return Err(ConfigError::provider_error(
                "vault",
                format!("invalid secret name: {}", name),
            ));
        }

        Ok(())
    }
}

impl ConfigProvider for VaultConfigProvider {
    fn get_raw(&self, key: &str) -> Result<Option<Value>, ConfigError> {
        match self.inner.get_raw(key)? {
            Some(value) => Ok(Some(self.interpolate_secrets(value)?)),
            None => Ok(None),
        }
    }

    fn has(&self, key: &str) -> bool {
        self.inner.has(key)
    }

    fn provider_name(&self) -> &str {
        "vault"
    }
}
