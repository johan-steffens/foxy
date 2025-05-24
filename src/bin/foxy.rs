// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal CLI wrapper so the library can run as a stand-alone proxy.
//!
//!  Build it with `cargo build --release --bin foxy`
//!  The binary honours FOXY_CONFIG_FILE or falls back to /etc/foxy/config.toml.

use std::env;
use std::error::Error;
use foxy::{Foxy, init_logging, log_info, log_error, log_warning};
use log::LevelFilter;

#[cfg(feature = "opentelemetry")]
use foxy::opentelemetry::OpenTelemetryConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging with appropriate level
    let log_level = match env::var("RUST_LOG_LEVEL").ok().as_deref() {
        Some("trace") => LevelFilter::Trace,
        Some("debug") => LevelFilter::Debug,
        Some("info") => LevelFilter::Info,
        Some("warn") => LevelFilter::Warn,
        Some("error") => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    init_logging(Some(log_level));
    
    log_info("Foxy", "Starting proxy server");
    
    // Prefer FOXY_CONFIG_FILE when present so the container user can
    // `docker run -v $(pwd)/config.toml:/etc/foxy/config.toml ...`
    let file_from_env = env::var("FOXY_CONFIG_FILE").ok();

    // Base loader always pulls env vars; file path is optional.
    let mut loader = Foxy::loader().with_env_vars();
    if let Some(ref path) = file_from_env {
        log_info("Config", format!("Using configuration from {}", path));
        loader = loader.with_config_file(path);
    } else {
        // Conventional default inside the image
        let fallback_path = "/etc/foxy/config.toml";
        log_info("Config", format!("No FOXY_CONFIG_FILE env var found. Attempting to use default configuration path: {}", fallback_path));

        if !std::path::Path::new(fallback_path).exists() {
            log_warning("Config", format!("Default configuration file {} does not exist.", fallback_path));
            panic!("No configuration file found.")
        }
        
        loader = loader.with_config_file(fallback_path);
    }

    // Build
    let proxy = match loader.build().await {
        Ok(p) => p,
        Err(e) => {
            log_error("Startup", format!("Failed to build proxy: {}", e));
            return Err(e.into());
        }
    };

    // Initialise OpenTelemetry
    #[cfg(feature = "opentelemetry")]
    {
        match proxy.config().get::<OpenTelemetryConfig>("proxy.opentelemetry") {
            Ok(Some(otel_config)) => {
                if !otel_config.endpoint.is_empty() {
                    foxy::opentelemetry::init(Some(otel_config)).unwrap_or_else(|err| {
                        log_error("Startup", format!("Failed to initialise OpenTelemetry: {}", err));
                    });
                } else {
                    log_info("Startup", "OpenTelemetry endpoint is not configured. Skipping initialization.");
                }
            }
            Ok(None) => {
                log_info("Startup", "OpenTelemetry configuration not found. Skipping initialization.");
            }
            Err(e) => {
                log_error("Startup", format!("Failed to read OpenTelemetry configuration: {}", e));
            }
        }   
    }
    
    match proxy.start().await {
        Ok(_) => {
            log_info("Foxy", "Proxy server stopped gracefully");
        },
        Err(e) => {
            log_error("Foxy", format!("Proxy server failed: {}", e));
            return Err(e.into());
        }
    }
    
    Ok(())
}
