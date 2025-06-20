// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Logging utilities for Foxy.
//!
//! This module provides centralized logging configuration and helper functions
//! for consistent logging throughout the application.
//!
//! Two logging systems are supported:
//! 1. Traditional logging via env_logger (default)
//! 2. Structured logging via slog with JSON output support

pub mod structured;
pub mod config;
pub mod wrapper;
pub mod middleware;

#[cfg(test)]
mod tests;

use log::{debug, error, info, trace, warn, LevelFilter};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::logging::config::LoggingConfig;
use crate::logging::structured::{LoggerGuard, init_global_logger};

static INIT: Once = Once::new();
static USING_STRUCTURED: AtomicBool = AtomicBool::new(false);
static mut LOGGER_GUARD: Option<LoggerGuard> = None;

/// Initialize logging with the specified level and configuration.
///
/// This function ensures logging is only initialized once.
pub fn init_with_config(level: LevelFilter, config: &LoggingConfig) {
    INIT.call_once(|| {
        log::set_max_level(level);

        if config.structured {
            let logger_config = config.to_logger_config();
            let guard = init_global_logger(&logger_config);

            // Keep the logger alive
            unsafe { LOGGER_GUARD = Some(guard); }
            USING_STRUCTURED.store(true, Ordering::SeqCst);
        } else {
            // Fallback to env_logger, using our determined level as the default.
            // The RUST_LOG env var can still override this if it was set.
            let env = env_logger::Env::default().filter_or("RUST_LOG", level.as_str());
            env_logger::Builder::from_env(env)
                .format_timestamp_millis()
                .format_target(true)
                .init();
        }

        info!("Logging initialized at level: {}", log::max_level());
    });
}

/// Check if structured logging is enabled
pub fn is_structured_logging() -> bool {
    USING_STRUCTURED.load(Ordering::SeqCst)
}

/// Log an error with context and return the error.
///
/// This is useful for logging errors in a chain of Results.
pub fn log_error<E: std::fmt::Display>(context: &str, err: E) -> E {
    if is_structured_logging() {
        slog_scope::error!("{}", err; "context" => context);
    } else {
        error!("{context}: {err}");
    }
    err
}

/// Log a warning with context.
pub fn log_warning<E: std::fmt::Display>(context: &str, err: E) {
    if is_structured_logging() {
        slog_scope::warn!("{}", err; "context" => context);
    } else {
        warn!("{context}: {err}");
    }
}

/// Log a debug message with context.
pub fn log_debug<M: std::fmt::Display>(context: &str, msg: M) {
    if is_structured_logging() {
        slog_scope::debug!("{}", msg; "context" => context);
    } else {
        debug!("{context}: {msg}");
    }
}

/// Log a trace message with context.
pub fn log_trace<M: std::fmt::Display>(context: &str, msg: M) {
    if is_structured_logging() {
        slog_scope::trace!("{}", msg; "context" => context);
    } else {
        trace!("{context}: {msg}");
    }
}

/// Log an info message with context.
pub fn log_info<M: std::fmt::Display>(context: &str, msg: M) {
    if is_structured_logging() {
        slog_scope::info!("{}", msg; "context" => context);
    } else {
        info!("{context}: {msg}");
    }
}

/// Log a message with additional context fields
pub fn log_with_context(
    level: log::Level,
    message: impl std::fmt::Display,
    context: &str,
    fields: &[(&'static str, String)]
) {
    if is_structured_logging() {
        match level {
            log::Level::Error => {
                let logger = slog_scope::logger();
                let context_str = context.to_string(); // Clone to extend lifetime
                let logger = logger.new(slog::o!("context" => context_str));
                let logger = add_fields_to_logger(logger, fields);
                slog::error!(logger, "{}", message);
            },
            log::Level::Warn => {
                let logger = slog_scope::logger();
                let context_str = context.to_string(); // Clone to extend lifetime
                let logger = logger.new(slog::o!("context" => context_str));
                let logger = add_fields_to_logger(logger, fields);
                slog::warn!(logger, "{}", message);
            },
            log::Level::Info => {
                let logger = slog_scope::logger();
                let context_str = context.to_string(); // Clone to extend lifetime
                let logger = logger.new(slog::o!("context" => context_str));
                let logger = add_fields_to_logger(logger, fields);
                slog::info!(logger, "{}", message);
            },
            log::Level::Debug => {
                let logger = slog_scope::logger();
                let context_str = context.to_string(); // Clone to extend lifetime
                let logger = logger.new(slog::o!("context" => context_str));
                let logger = add_fields_to_logger(logger, fields);
                slog::debug!(logger, "{}", message);
            },
            log::Level::Trace => {
                let logger = slog_scope::logger();
                let context_str = context.to_string(); // Clone to extend lifetime
                let logger = logger.new(slog::o!("context" => context_str));
                let logger = add_fields_to_logger(logger, fields);
                slog::trace!(logger, "{}", message);
            },
        }
    } else {
        // Fall back to standard logging with context
        match level {
            log::Level::Error => crate::error!("{}: {}", context, message),
            log::Level::Warn => crate::warn!("{}: {}", context, message),
            log::Level::Info => crate::info!("{}: {}", context, message),
            log::Level::Debug => crate::debug!("{}: {}", context, message),
            log::Level::Trace => crate::trace!("{}: {}", context, message),
        }
    }
}

/// Helper function to add fields to a logger
fn add_fields_to_logger(logger: slog::Logger, fields: &[(&'static str, String)]) -> slog::Logger {
    let mut result = logger;
    for (k, v) in fields {
        let v_clone = v.clone(); // Clone the value to extend its lifetime
        result = result.new(slog::o!(*k => v_clone));
    }
    result
}
