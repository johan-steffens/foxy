// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Structured logging implementation for Foxy.
//!
//! This module provides structured logging capabilities using slog,
//! with support for JSON output and contextual information.

use slog::{Drain, Logger, o};
use slog_async::Async;
use slog_json::Json;
use slog_term::{FullFormat, TermDecorator};
use std::io;
use uuid::Uuid;

/// Structured logging format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable terminal output
    Terminal,
    /// JSON formatted output
    Json,
}

/// Structured logger configuration
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Output format (Terminal or JSON)
    pub format: LogFormat,
    /// Log level
    pub level: slog::Level,
    /// Whether to include source code location
    pub include_location: bool,
    /// Whether to include thread ID
    pub include_thread_id: bool,
    /// Additional static key-value pairs to include in all logs
    pub static_fields: Vec<(String, String)>,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Terminal,
            level: slog::Level::Info,
            include_location: true,
            include_thread_id: true,
            static_fields: Vec::new(),
        }
    }
}

/// Create a structured logger with the given configuration
pub fn create_logger(config: &LoggerConfig) -> Logger {
    match config.format {
        LogFormat::Terminal => create_terminal_logger(config),
        LogFormat::Json => create_json_logger(config),
    }
}

/// Create a terminal-formatted logger
fn create_terminal_logger(config: &LoggerConfig) -> Logger {
    let decorator = TermDecorator::new().build();
    let drain = FullFormat::new(decorator).build().fuse();
    
    let drain = drain.filter_level(config.level).fuse();
    let drain = Async::new(drain).build().fuse();
    
    // Build the base logger
    let mut logger = Logger::root(drain, o!());
    
    // Add static fields
    for (key, value) in &config.static_fields {
        // Use &str slices instead of String for keys
        let key_str: &'static str = Box::leak(key.clone().into_boxed_str());
        logger = logger.new(o!(key_str => value.clone()));
    }
    
    logger
}

/// Create a JSON-formatted logger
fn create_json_logger(config: &LoggerConfig) -> Logger {
    let drain = Json::new(io::stdout())
        .add_default_keys()
        .build()
        .fuse();
    
    let drain = drain.filter_level(config.level).fuse();
    let drain = Async::new(drain).build().fuse();
    
    // Build the base logger
    let mut logger = Logger::root(drain, o!());
    
    // Add static fields
    for (key, value) in &config.static_fields {
        // Use &str slices instead of String for keys
        let key_str: &'static str = Box::leak(key.clone().into_boxed_str());
        logger = logger.new(o!(key_str => value.clone()));
    }
    
    logger
}

/// Generate a new trace ID
pub fn generate_trace_id() -> String {
    Uuid::new_v4().to_string()
}

/// Create a child logger with request context
pub fn with_request_context(logger: &Logger, request_info: &RequestInfo) -> Logger {
    logger.new(o!(
        "trace_id" => request_info.trace_id.clone(),
        "method" => request_info.method.clone(),
        "path" => request_info.path.clone(),
        "remote_addr" => request_info.remote_addr.clone(),
        "user_agent" => request_info.user_agent.clone(),
    ))
}

/// Request information for logging context
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// Unique trace ID for the request
    pub trace_id: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Remote address
    pub remote_addr: String,
    /// User agent
    pub user_agent: String,
    /// Start time in milliseconds since epoch
    pub start_time_ms: u128,
}

impl RequestInfo {
    /// Create a new RequestInfo from request details
    pub fn new(method: String, path: String, remote_addr: String, user_agent: String) -> Self {
        Self {
            trace_id: generate_trace_id(),
            method,
            path,
            remote_addr,
            user_agent,
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        }
    }
    
    /// Calculate elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .saturating_sub(self.start_time_ms)
    }
}

/// Global logger guard that keeps the logger alive
pub struct LoggerGuard {
    _guard: slog_scope::GlobalLoggerGuard,
}

/// Initialize the global structured logger
pub fn init_global_logger(config: &LoggerConfig) -> LoggerGuard {
    let logger = create_logger(config);
    let guard = slog_scope::set_global_logger(logger);
    
    LoggerGuard { _guard: guard }
}
