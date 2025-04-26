// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example demonstrating how to use the Foxy loader for initialization.

use foxy::Foxy;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Foxy Loader Example");
    println!("------------------");

    // Example 1: Initialize with defaults
    println!("\nExample 1: Initialize with defaults");
    let foxy = Foxy::loader().build()?;
    println!("Foxy initialized with default configuration");

    // Example 2: Initialize with a configuration file
    println!("\nExample 2: Initialize with a configuration file");
    println!("Attempting to load examples/config.toml...");

    match Foxy::loader().with_config_file("examples/config.toml").build() {
        Ok(foxy) => {
            println!("Configuration file loaded successfully");

            // Access some configuration values
            if let Ok(Some(host)) = foxy.config().get::<String>("server.host") {
                println!("Server host: {}", host);
            }

            if let Ok(port) = foxy.config().get_or_default("server.port", 8080) {
                println!("Server port: {}", port);
            }
        },
        Err(e) => {
            println!("Failed to load configuration file: {}", e);
            println!("(This is expected if examples/config.toml doesn't exist)");
        }
    }

    // Example 3: Initialize with environment variables
    println!("\nExample 3: Initialize with environment variables");

    // Set some environment variables for testing
    unsafe {
        std::env::set_var("FOXY_TEST_VALUE", "from environment");
        std::env::set_var("FOXY_SERVER_PORT", "9090");
    }

    let foxy = Foxy::loader().with_env_vars().build()?;

    if let Ok(Some(value)) = foxy.config().get::<String>("test.value") {
        println!("test.value: {}", value);
    } else {
        println!("test.value not found in environment variables");
    }

    if let Ok(port) = foxy.config().get_or_default::<u16>("server.port", 8080) {
        println!("Server port: {}", port);
    }

    // Clean up
    unsafe {
        std::env::remove_var("FOXY_TEST_VALUE");
        std::env::remove_var("FOXY_SERVER_PORT");
    }

    // Example 4: Initialize with a custom configuration provider
    println!("\nExample 4: Initialize with a custom configuration provider");

    // Define a custom configuration provider
    #[derive(Debug)]
    struct CustomProvider;

    impl foxy::ConfigProvider for CustomProvider {
        fn get_raw(&self, key: &str) -> Result<Option<serde_json::Value>, foxy::ConfigError> {
            match key {
                "custom.value" => Ok(Some(serde_json::json!("custom provider value"))),
                "server.port" => Ok(Some(serde_json::json!(7070))),
                _ => Ok(None),
            }
        }

        fn has(&self, key: &str) -> bool {
            matches!(key, "custom.value" | "server.port")
        }

        fn provider_name(&self) -> &str {
            "custom_provider"
        }
    }

    let foxy = Foxy::loader()
        .with_provider(CustomProvider)
        .build()?;

    if let Ok(Some(value)) = foxy.config().get::<String>("custom.value") {
        println!("custom.value: {}", value);
    }

    if let Ok(port) = foxy.config().get::<u16>("server.port") {
        println!("Server port: {:?}", port);
    }

    // Example 5: Combined configuration with priority
    println!("\nExample 5: Combined configuration with priority");

    unsafe {
        std::env::set_var("FOXY_PRIORITY", "env has highest priority");
    }

    let foxy = Foxy::loader()
        .with_env_vars()                           // Highest priority
        .with_provider(CustomProvider)             // Middle priority
        .with_config_file("examples/config.toml")  // Lowest priority (may fail, that's OK)
        .build()?;

    if let Ok(Some(value)) = foxy.config().get::<String>("priority") {
        println!("priority: {}", value);
    } else {
        println!("priority not found in any configuration source");
    }

    unsafe {
        std::env::remove_var("FOXY_PRIORITY");
    }

    println!("\nAll examples completed successfully!");
    Ok(())
}