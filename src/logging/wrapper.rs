// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Logging wrapper functions that route to either structured logging or standard logging.
//!
//! This module provides wrapper functions around the standard log crate's macros
//! to ensure all logging goes through our logging system.

use crate::logging::is_structured_logging;

/// Log an error message
pub fn error(args: std::fmt::Arguments) {
    if is_structured_logging() {
        slog_scope::error!("{}", args);
    } else {
        crate::error!("{}", args);
    }
}

/// Log a warning message
pub fn warn(args: std::fmt::Arguments) {
    if is_structured_logging() {
        slog_scope::warn!("{}", args);
    } else {
        crate::warn!("{}", args);
    }
}

/// Log an info message
pub fn info(args: std::fmt::Arguments) {
    if is_structured_logging() {
        slog_scope::info!("{}", args);
    } else {
        crate::info!("{}", args);
    }
}

/// Log a debug message
pub fn debug(args: std::fmt::Arguments) {
    if is_structured_logging() {
        slog_scope::debug!("{}", args);
    } else {
        crate::debug!("{}", args);
    }
}

/// Log a trace message
pub fn trace(args: std::fmt::Arguments) {
    if is_structured_logging() {
        slog_scope::trace!("{}", args);
    } else {
        crate::trace!("{}", args);
    }
}

/// Macro to log an error message
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        $crate::logging::wrapper::error(format_args!($($arg)+))
    };
}

/// Macro to log a warning message
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        $crate::logging::wrapper::warn(format_args!($($arg)+))
    };
}

/// Macro to log an info message
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        $crate::logging::wrapper::info(format_args!($($arg)+))
    };
}

/// Macro to log a debug message
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        $crate::logging::wrapper::debug(format_args!($($arg)+))
    };
}

/// Macro to log a trace message
#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => {
        $crate::logging::wrapper::trace(format_args!($($arg)+))
    };
}

/// Format macros that support the same formatting as log::* macros but with context
#[macro_export]
macro_rules! error_fmt {
    ($context:expr, $($arg:tt)+) => {
        if $crate::logging::is_structured_logging() {
            slog_scope::error!("{}", format_args!($($arg)+); "context" => $context);
        } else {
            crate::error!("{}: {}", $context, format_args!($($arg)+));
        }
    };
}

/// Macro to log a warning message with context
#[macro_export]
macro_rules! warn_fmt {
    ($context:expr, $($arg:tt)+) => {
        if $crate::logging::is_structured_logging() {
            slog_scope::warn!("{}", format_args!($($arg)+); "context" => $context);
        } else {
            crate::warn!("{}: {}", $context, format_args!($($arg)+));
        }
    };
}

/// Macro to log an info message with context
#[macro_export]
macro_rules! info_fmt {
    ($context:expr, $($arg:tt)+) => {
        if $crate::logging::is_structured_logging() {
            slog_scope::info!("{}", format_args!($($arg)+); "context" => $context);
        } else {
            crate::info!("{}: {}", $context, format_args!($($arg)+));
        }
    };
}

/// Macro to log a debug message with context
#[macro_export]
macro_rules! debug_fmt {
    ($context:expr, $($arg:tt)+) => {
        if $crate::logging::is_structured_logging() {
            slog_scope::debug!("{}", format_args!($($arg)+); "context" => $context);
        } else {
            crate::debug!("{}: {}", $context, format_args!($($arg)+));
        }
    };
}

/// Macro to log a trace message with context
#[macro_export]
macro_rules! trace_fmt {
    ($context:expr, $($arg:tt)+) => {
        if $crate::logging::is_structured_logging() {
            slog_scope::trace!("{}", format_args!($($arg)+); "context" => $context);
        } else {
            crate::trace!("{}: {}", $context, format_args!($($arg)+));
        }
    };
}
