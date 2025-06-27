// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Configuration for logging.

use crate::logging::structured::{LogFormat, LoggerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Whether to use structured logging
    #[serde(default = "default_false")]
    pub structured: bool,

    /// Log format (terminal or json)
    #[serde(default = "default_format")]
    pub format: String,

    /// Log level
    #[serde(default = "default_level")]
    pub level: String,

    /// Include source code location
    #[serde(default = "default_true")]
    pub include_location: bool,

    /// Include thread ID
    #[serde(default = "default_true")]
    pub include_thread_id: bool,

    /// Include trace ID in logs
    #[serde(default = "default_true")]
    pub include_trace_id: bool,

    /// Propagate trace ID from request headers
    #[serde(default = "default_true")]
    pub propagate_trace_id: bool,

    /// Header name for trace ID
    #[serde(default = "default_trace_header")]
    pub trace_id_header: String,

    /// Static fields to include in all logs
    #[serde(default)]
    pub static_fields: HashMap<String, String>,
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_format() -> String {
    "terminal".to_string()
}

fn default_level() -> String {
    "info".to_string()
}

fn default_trace_header() -> String {
    "X-Trace-ID".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            structured: false,
            format: default_format(),
            level: default_level(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: true,
            trace_id_header: default_trace_header(),
            static_fields: HashMap::new(),
        }
    }
}

impl LoggingConfig {
    /// Convert to logger config
    pub fn to_logger_config(&self) -> LoggerConfig {
        LoggerConfig {
            format: match self.format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                _ => LogFormat::Terminal,
            },
            level: match self.level.to_lowercase().as_str() {
                "trace" => slog::Level::Trace,
                "debug" => slog::Level::Debug,
                "info" => slog::Level::Info,
                "warn" => slog::Level::Warning,
                "error" => slog::Level::Error,
                "critical" => slog::Level::Critical,
                _ => slog::Level::Info,
            },
            include_location: self.include_location,
            include_thread_id: self.include_thread_id,
            static_fields: self.static_fields.clone(),
        }
    }
}
