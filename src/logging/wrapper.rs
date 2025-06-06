// In src/logging/wrapper.rs

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Logging wrapper macros that route all messages to the standard `log` facade.
//! The `slog_stdlog` bridge (configured in `structured.rs`) handles forwarding
//! to `slog` when structured logging is enabled. This unified approach is
//! simpler and more robust.

/// Macro to log an error message with context.
#[macro_export]
macro_rules! error_fmt {
    ($context:expr, $($arg:tt)+) => {
        log::error!("[{}] {}", $context, format_args!($($arg)+))
    };
}

/// Macro to log a warning message with context.
#[macro_export]
macro_rules! warn_fmt {
    ($context:expr, $($arg:tt)+) => {
        log::warn!("[{}] {}", $context, format_args!($($arg)+))
    };
}

/// Macro to log an info message with context.
#[macro_export]
macro_rules! info_fmt {
    ($context:expr, $($arg:tt)+) => {
        log::info!("[{}] {}", $context, format_args!($($arg)+))
    };
}

/// Macro to log a debug message with context.
#[macro_export]
macro_rules! debug_fmt {
    ($context:expr, $($arg:tt)+) => {
        log::debug!("[{}] {}", $context, format_args!($($arg)+))
    };
}

/// Macro to log a trace message with context.
#[macro_export]
macro_rules! trace_fmt {
    ($context:expr, $($arg:tt)+) => {
        log::trace!("[{}] {}", $context, format_args!($($arg)+))
    };
}

// The following simple wrapper macros and functions are no longer necessary
// with this unified approach, as standard `log::*` macros can be used directly.
// You may want to remove them from here and `src/logging/mod.rs` to clean up the code.

/// Macro to log an error message
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        log::error!($($arg)+)
    };
}

/// Macro to log a warning message
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        log::warn!($($arg)+)
    };
}

/// Macro to log an info message
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        log::info!($($arg)+)
    };
}

/// Macro to log a debug message
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        log::debug!($($arg)+)
    };
}

/// Macro to log a trace message
#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => {
        log::trace!($($arg)+)
    };
}