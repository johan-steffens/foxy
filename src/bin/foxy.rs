// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal CLI wrapper so the library can run as a stand-alone proxy.
//!
//!  Build it with `cargo build --release --bin foxy`
//!  The binary honours FOXY_CONFIG_FILE or falls back to /etc/foxy/config.toml.

use std::env;
use std::error::Error;
use foxy::{info_fmt, Foxy};
#[cfg(feature = "opentelemetry")]
use foxy::opentelemetry::OpenTelemetryConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting Foxy");
    
    // Prefer FOXY_CONFIG_FILE when present so the container user can
    // `docker run -v $(pwd)/config.toml:/etc/foxy/config.toml ...`
    let file_from_env = env::var("FOXY_CONFIG_FILE").ok();

    // Base loader always pulls env vars; file path is optional.
    let mut loader = Foxy::loader().with_env_vars();
    if let Some(ref path) = file_from_env {
        println!("Using configuration from {path}");
        loader = loader.with_config_file(path);
    } else {
        // Conventional default inside the image
        let fallback_path = "/etc/foxy/config.toml";
        println!("No FOXY_CONFIG_FILE env var found. Attempting to use default configuration path: {fallback_path}");

        if !std::path::Path::new(fallback_path).exists() {
            println!("Default configuration file {fallback_path} does not exist.");
            return Err(Box::from("No configuration file found."));
        }
        
        loader = loader.with_config_file(fallback_path);
    }

    // Build
    let proxy = match loader.build().await {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to build proxy: {e}");
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
                        error_fmt!("Startup", "Failed to initialise OpenTelemetry: {}", err);
                    });
                } else {
                    info_fmt!("Startup", "OpenTelemetry endpoint is not configured. Skipping initialization.");
                }
            }
            Ok(None) => {
                info_fmt!("Startup", "OpenTelemetry configuration not found. Skipping initialization.");
            }
            Err(e) => {
                info_fmt!("Startup", "Failed to read OpenTelemetry configuration: {}", e);
            }
        }   
    }
    
    match proxy.start().await {
        Ok(_) => {
            info_fmt!("Foxy", "Proxy server stopped gracefully");
        },
        Err(e) => {
            info_fmt!("Foxy", "Proxy server failed: {}", e);
            return Err(e.into());
        }
    }
    
    Ok(())
}
