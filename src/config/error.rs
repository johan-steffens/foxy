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