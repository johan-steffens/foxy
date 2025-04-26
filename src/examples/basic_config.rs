//! Example demonstrating the configuration system in Foxy.

use foxy::config::{Config, EnvConfigProvider, FileConfigProvider};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Example 1: Load from a single file
    println!("Example 1: Loading from a single file");
    match Config::default_file("examples/config.toml") {
        Ok(config) => {
            // Access some configuration values
            let host: String = config.get("server.host")?.unwrap_or_else(|| "localhost".to_string());
            let port: u16 = config.get_or_default("server.port", 8080)?;
            println!("Server configured at {}:{}", host, port);

            // Access a value with a default
            let timeout: u32 = config.get_or_default("timeout", 30)?;
            println!("Timeout: {} seconds", timeout);
        },
        Err(e) => {
            println!("Failed to load configuration: {}", e);
            println!("(This is expected if examples/config.toml doesn't exist)");
        }
    }

    // Example 2: Multiple configuration sources with priority
    println!("\nExample 2: Multiple configuration sources");

    // Create a layered configuration with environment variables taking precedence
    let layered_config = Config::builder()
        // First try environment variables (higher priority)
        .with_provider(EnvConfigProvider::default())
        // Then fall back to file (lower priority)
        .with_provider(
            FileConfigProvider::new("examples/config.toml").unwrap_or_else(|_| {
                println!("Config file not found, using empty file provider");
                // Create an empty provider for demonstration
                FileConfigProvider::new("examples/empty.json").unwrap_or_else(|_| {
                    panic!("Failed to create empty file provider");
                })
            })
        )
        .build();

    // Set an environment variable for testing
    unsafe {
        std::env::set_var("FOXY_TEST_VALUE", "from environment");
    }

    // This would come from the environment variable
    let env_value: Option<String> = layered_config.get("test.value")?;
    println!("test.value: {:?}", env_value);

    // Clean up
    unsafe {
        std::env::remove_var("FOXY_TEST_VALUE");
    }

    Ok(())
}