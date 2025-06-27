// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Error types for the configuration module.

use std::fmt;
use std::io;
use thiserror::Error;

/// Errors that can occur during configuration operations.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// The requested configuration key was not found.
    #[error("configuration key not found")]
    NotFound,

    /// An error occurred while parsing or deserializing a configuration value.
    #[error("failed to parse configuration: {0}")]
    ParseError(String),

    /// An IO error occurred (e.g., while reading a configuration file).
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// An error related to a specific configuration provider.
    #[error("provider error: {provider}: {message}")]
    ProviderError { provider: String, message: String },

    /// A generic error.
    #[error("{0}")]
    Other(String),
}

impl ConfigError {
    /// Create a new provider error.
    pub fn provider_error<P: fmt::Display, M: fmt::Display>(provider: P, message: M) -> Self {
        Self::ProviderError {
            provider: provider.to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("NotFound"));
    }

    #[test]
    fn test_config_error_debug_with_data() {
        let error = ConfigError::ParseError("test".to_string());
        let debug_str = format!("{:?}", error);
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
                ConfigError::NotFound => {},
                ConfigError::ParseError(_) => {},
                ConfigError::IoError(_) => {},
                ConfigError::ProviderError { .. } => {},
                ConfigError::Other(_) => {},
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
}
