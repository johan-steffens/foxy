// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Logging utilities for Foxy.
//!
//! This module provides centralized logging configuration and helper functions
//! for consistent logging throughout the application.

use log::{debug, error, info, trace, warn, LevelFilter};
use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize logging with the specified level.
///
/// This function ensures logging is only initialized once.
pub fn init(level: Option<LevelFilter>) {
    INIT.call_once(|| {
        let env = env_logger::Env::default()
            .filter_or("RUST_LOG", level.map_or("info", |l| match l {
                LevelFilter::Trace => "trace",
                LevelFilter::Debug => "debug",
                LevelFilter::Info => "info",
                LevelFilter::Warn => "warn",
                LevelFilter::Error => "error",
                LevelFilter::Off => "off",
            }));

        env_logger::Builder::from_env(env)
            .format_timestamp_millis()
            .format_target(true)
            .init();

        info!("Logging initialized at level: {}", log::max_level());
    });
}

/// Log an error with context and return the error.
///
/// This is useful for logging errors in a chain of Results.
pub fn log_error<E: std::fmt::Display>(context: &str, err: E) -> E {
    error!("{}: {}", context, err);
    err
}

/// Log a warning with context.
pub fn log_warning<E: std::fmt::Display>(context: &str, err: E) {
    warn!("{}: {}", context, err);
}

/// Log a debug message with context.
pub fn log_debug<M: std::fmt::Display>(context: &str, msg: M) {
    debug!("{}: {}", context, msg);
}

/// Log a trace message with context.
pub fn log_trace<M: std::fmt::Display>(context: &str, msg: M) {
    trace!("{}: {}", context, msg);
}

/// Log an info message with context.
pub fn log_info<M: std::fmt::Display>(context: &str, msg: M) {
    info!("{}: {}", context, msg);
}
