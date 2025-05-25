// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Structured logging implementation for Foxy.

use slog::{Drain, Logger, o};
use slog_async::Async;
use slog_term::{TermDecorator, CompactFormat};
use slog_json::Json;
use std::sync::Arc;
use std::io;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

/// Logger configuration
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Log format (terminal or json)
    pub format: LogFormat,
    /// Log level
    pub level: slog::Level,
    /// Include source code location
    pub include_location: bool,
    /// Include thread ID
    pub include_thread_id: bool,
    /// Static fields to include in all logs
    pub static_fields: std::collections::HashMap<String, String>,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Terminal,
            level: slog::Level::Info,
            include_location: true,
            include_thread_id: true,
            static_fields: std::collections::HashMap::new(),
        }
    }
}

/// Log format
#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    /// Human-readable terminal output
    Terminal,
    /// Machine-parseable JSON output
    Json,
}

/// Request information for logging
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// Trace ID for request correlation
    pub trace_id: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Remote address
    pub remote_addr: String,
    /// User agent
    pub user_agent: String,
    /// Request start time (milliseconds since epoch)
    pub start_time_ms: u128,
}

impl RequestInfo {
    /// Calculate elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .saturating_sub(self.start_time_ms)
    }
}

/// Generate a new trace ID
pub fn generate_trace_id() -> String {
    Uuid::new_v4().to_string()
}

/// Initialize the global logger
pub fn init_global_logger(config: &LoggerConfig) -> LoggerGuard {
    let drain = match config.format {
        LogFormat::Terminal => {
            let decorator = TermDecorator::new().build();
            let drain = CompactFormat::new(decorator).build().fuse();
            Async::new(drain).build().fuse()
        }
        LogFormat::Json => {
            let drain = Json::new(io::stdout())
                .add_default_keys()
                .build()
                .fuse();
            Async::new(drain).build().fuse()
        }
    };

    let drain = drain.filter_level(config.level).fuse();

    // Add static fields
    let mut logger = Logger::root(drain, o!());
    for (key, value) in &config.static_fields {
        let key_str: &'static str = Box::leak(key.clone().into_boxed_str());
        logger = logger.new(o!(key_str => value.clone()));
    }

    // Set up the global logger
    let guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init().unwrap();

    LoggerGuard { _guard: guard }
}

/// Guard for the global logger
pub struct LoggerGuard {
    _guard: slog_scope::GlobalLoggerGuard,
}
