// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Structured logging implementation for Foxy.

use slog::{Drain, Logger, o};
use slog_async::Async;
use slog_json::Json;
use slog_term::{CompactFormat, TermDecorator};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
            // Create a custom JSON drain with our specific key names
            let drain = Json::new(io::stdout())
                .set_pretty(false)
                .set_newlines(true)
                // Use @timestamp for timestamp
                .add_key_value(o!("@timestamp" => slog::PushFnValue(|_record, ser| {
                    let time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                    ser.emit(time)
                })))
                // Use message for the message
                .add_key_value(o!("message" => slog::PushFnValue(|record, ser| {
                    ser.emit(record.msg())
                })))
                // Add level without any prefix
                .add_key_value(o!("level" => slog::PushFnValue(|record, ser| {
                    let level = record.level().as_str();
                    ser.emit(level)
                })))
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

    let log_level_filter = match config.level {
        slog::Level::Trace => log::Level::Trace,
        slog::Level::Debug => log::Level::Debug,
        slog::Level::Info => log::Level::Info,
        slog::Level::Warning => log::Level::Warn,
        slog::Level::Error => log::Level::Error,
        slog::Level::Critical => log::Level::Error,
    };

    let _ = slog_stdlog::init_with_level(log_level_filter);

    LoggerGuard { _guard: guard }
}

/// Guard for the global logger
pub struct LoggerGuard {
    _guard: slog_scope::GlobalLoggerGuard,
}
