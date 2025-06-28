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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_logger_config_default() {
        let config = LoggerConfig::default();

        assert_eq!(config.format, LogFormat::Terminal);
        assert_eq!(config.level, slog::Level::Info);
        assert!(config.include_location);
        assert!(config.include_thread_id);
        assert!(config.static_fields.is_empty());
    }

    #[test]
    fn test_logger_config_custom() {
        let mut static_fields = HashMap::new();
        static_fields.insert("service".to_string(), "foxy".to_string());
        static_fields.insert("version".to_string(), "1.0.0".to_string());

        let config = LoggerConfig {
            format: LogFormat::Json,
            level: slog::Level::Debug,
            include_location: false,
            include_thread_id: false,
            static_fields,
        };

        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.level, slog::Level::Debug);
        assert!(!config.include_location);
        assert!(!config.include_thread_id);
        assert_eq!(config.static_fields.len(), 2);
        assert_eq!(
            config.static_fields.get("service"),
            Some(&"foxy".to_string())
        );
        assert_eq!(
            config.static_fields.get("version"),
            Some(&"1.0.0".to_string())
        );
    }

    #[test]
    fn test_logger_config_debug() {
        let config = LoggerConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("LoggerConfig"));
        assert!(debug_str.contains("format"));
        assert!(debug_str.contains("level"));
        assert!(debug_str.contains("include_location"));
        assert!(debug_str.contains("include_thread_id"));
        assert!(debug_str.contains("static_fields"));
    }

    #[test]
    fn test_logger_config_clone() {
        let mut config = LoggerConfig::default();
        config
            .static_fields
            .insert("test".to_string(), "value".to_string());

        let cloned = config.clone();

        assert_eq!(config.format, cloned.format);
        assert_eq!(config.level, cloned.level);
        assert_eq!(config.include_location, cloned.include_location);
        assert_eq!(config.include_thread_id, cloned.include_thread_id);
        assert_eq!(config.static_fields, cloned.static_fields);
    }

    #[test]
    fn test_log_format_equality() {
        assert_eq!(LogFormat::Terminal, LogFormat::Terminal);
        assert_eq!(LogFormat::Json, LogFormat::Json);
        assert_ne!(LogFormat::Terminal, LogFormat::Json);
        assert_ne!(LogFormat::Json, LogFormat::Terminal);
    }

    #[test]
    fn test_log_format_debug() {
        let terminal_debug = format!("{:?}", LogFormat::Terminal);
        let json_debug = format!("{:?}", LogFormat::Json);

        assert!(terminal_debug.contains("Terminal"));
        assert!(json_debug.contains("Json"));
    }

    #[test]
    fn test_log_format_clone() {
        let terminal = LogFormat::Terminal;
        let json = LogFormat::Json;

        let terminal_clone = terminal.clone();
        let json_clone = json.clone();

        assert_eq!(terminal, terminal_clone);
        assert_eq!(json, json_clone);
    }

    #[test]
    fn test_request_info_creation() {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let request_info = RequestInfo {
            trace_id: "test-trace-id".to_string(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            remote_addr: "127.0.0.1:8080".to_string(),
            user_agent: "test-agent".to_string(),
            start_time_ms: start_time,
        };

        assert_eq!(request_info.trace_id, "test-trace-id");
        assert_eq!(request_info.method, "GET");
        assert_eq!(request_info.path, "/api/test");
        assert_eq!(request_info.remote_addr, "127.0.0.1:8080");
        assert_eq!(request_info.user_agent, "test-agent");
        assert_eq!(request_info.start_time_ms, start_time);
    }

    #[test]
    fn test_request_info_elapsed_ms() {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .saturating_sub(100); // 100ms ago

        let request_info = RequestInfo {
            trace_id: "test".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            remote_addr: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            start_time_ms: start_time,
        };

        let elapsed = request_info.elapsed_ms();
        // Should be approximately 100ms, but allow for some variance
        assert!((90..=200).contains(&elapsed));
    }

    #[test]
    fn test_request_info_elapsed_ms_future_time() {
        // Test with a future start time (should return 0 due to saturating_sub)
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .saturating_add(1000); // 1 second in the future

        let request_info = RequestInfo {
            trace_id: "test".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            remote_addr: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            start_time_ms: future_time,
        };

        let elapsed = request_info.elapsed_ms();
        assert_eq!(elapsed, 0);
    }

    #[test]
    fn test_request_info_debug() {
        let request_info = RequestInfo {
            trace_id: "debug-test".to_string(),
            method: "POST".to_string(),
            path: "/debug".to_string(),
            remote_addr: "192.168.1.1".to_string(),
            user_agent: "debug-agent".to_string(),
            start_time_ms: 1234567890,
        };

        let debug_str = format!("{request_info:?}");
        assert!(debug_str.contains("RequestInfo"));
        assert!(debug_str.contains("debug-test"));
        assert!(debug_str.contains("POST"));
        assert!(debug_str.contains("/debug"));
        assert!(debug_str.contains("192.168.1.1"));
        assert!(debug_str.contains("debug-agent"));
        assert!(debug_str.contains("1234567890"));
    }

    #[test]
    fn test_request_info_clone() {
        let original = RequestInfo {
            trace_id: "clone-test".to_string(),
            method: "PUT".to_string(),
            path: "/clone".to_string(),
            remote_addr: "10.0.0.1".to_string(),
            user_agent: "clone-agent".to_string(),
            start_time_ms: 9876543210,
        };

        let cloned = original.clone();

        assert_eq!(original.trace_id, cloned.trace_id);
        assert_eq!(original.method, cloned.method);
        assert_eq!(original.path, cloned.path);
        assert_eq!(original.remote_addr, cloned.remote_addr);
        assert_eq!(original.user_agent, cloned.user_agent);
        assert_eq!(original.start_time_ms, cloned.start_time_ms);
    }

    #[test]
    fn test_generate_trace_id() {
        let trace_id1 = generate_trace_id();
        let trace_id2 = generate_trace_id();

        // Should be valid UUIDs
        assert!(uuid::Uuid::parse_str(&trace_id1).is_ok());
        assert!(uuid::Uuid::parse_str(&trace_id2).is_ok());

        // Should be different
        assert_ne!(trace_id1, trace_id2);

        // Should be the right length (UUID v4 string format)
        assert_eq!(trace_id1.len(), 36);
        assert_eq!(trace_id2.len(), 36);
    }

    #[test]
    fn test_generate_trace_id_format() {
        let trace_id = generate_trace_id();

        // Should match UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        let parts: Vec<&str> = trace_id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);

        // All parts should be hexadecimal
        for part in parts {
            assert!(part.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        }
    }

    #[test]
    fn test_init_global_logger_terminal() {
        let config = LoggerConfig {
            format: LogFormat::Terminal,
            level: slog::Level::Info,
            include_location: true,
            include_thread_id: true,
            static_fields: HashMap::new(),
        };

        // Test that the function returns a guard without panicking
        let _guard = init_global_logger(&config);

        // Test that the guard exists (this validates the logger was created)
        // We don't test actual logging to avoid global state conflicts in parallel tests
    }

    #[test]
    fn test_init_global_logger_json() {
        let config = LoggerConfig {
            format: LogFormat::Json,
            level: slog::Level::Debug,
            include_location: false,
            include_thread_id: false,
            static_fields: HashMap::new(),
        };

        // Test that the function returns a guard without panicking
        let _guard = init_global_logger(&config);

        // Test that the guard exists (this validates the logger was created)
        // We don't test actual logging to avoid global state conflicts in parallel tests
    }

    #[test]
    fn test_init_global_logger_with_static_fields() {
        let mut static_fields = HashMap::new();
        static_fields.insert("service".to_string(), "test-service".to_string());
        static_fields.insert("environment".to_string(), "test".to_string());

        let config = LoggerConfig {
            format: LogFormat::Terminal,
            level: slog::Level::Warning,
            include_location: true,
            include_thread_id: true,
            static_fields,
        };

        // Test that the function returns a guard without panicking
        let _guard = init_global_logger(&config);

        // Test that the guard exists (this validates the logger was created)
        // We don't test actual logging to avoid global state conflicts in parallel tests
    }
}
