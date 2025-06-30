// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Example demonstrating the vault-config feature.
//!
//! This example shows how to use the VaultConfigProvider to interpolate
//! secrets from the filesystem into configuration values.
//!
//! To run this example:
//! 1. Enable the vault-config feature: `cargo run --example vault_example --features vault-config`
//! 2. Create the vault directory and secret files (see setup instructions below)

#[cfg(feature = "vault-config")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use foxy::config::{Config, FileConfigProvider, VaultConfigProvider};
    use std::fs;
    use tempfile::tempdir;

    println!("Vault Config Example");
    println!("====================");

    // Create a temporary directory for this example
    let temp_dir = tempdir()?;
    let vault_dir = temp_dir.path().join("vault").join("secret");
    fs::create_dir_all(&vault_dir)?;

    // Create some example secret files
    fs::write(vault_dir.join("redis_password"), "super_secret_redis_pass")?;
    fs::write(vault_dir.join("db_password"), "my_database_password")?;
    fs::write(vault_dir.join("db_user"), "dbadmin")?;
    fs::write(vault_dir.join("api_key"), "sk-1234567890abcdef")?;
    fs::write(vault_dir.join("backup_host"), "backup.example.com")?;

    println!("Created vault directory: {}", vault_dir.display());
    println!("Secret files:");
    for entry in fs::read_dir(&vault_dir)? {
        let entry = entry?;
        let content = fs::read_to_string(entry.path())?;
        println!("  {}: {}", entry.file_name().to_string_lossy(), content);
    }
    println!();

    // Create a configuration file with secret references
    let config_file = temp_dir.path().join("config.json");
    let config_content = r#"{
  "server": {
    "listen": "0.0.0.0:8080",
    "secret": "${secret.redis_password}"
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "username": "admin",
    "password": "${secret.db_password}",
    "connection_string": "postgresql://${secret.db_user}:${secret.db_password}@localhost:5432/mydb"
  },
  "api": {
    "key": "${secret.api_key}",
    "endpoints": [
      "https://api.example.com",
      "https://${secret.backup_host}/api"
    ]
  },
  "logging": {
    "level": "info",
    "format": "json"
  }
}"#;
    fs::write(&config_file, config_content)?;

    println!("Configuration file content:");
    println!("{}", config_content);
    println!();

    // Create the configuration with vault interpolation
    let file_provider = FileConfigProvider::new(config_file.to_str().unwrap())?;
    let vault_provider = VaultConfigProvider::wrap(file_provider, vault_dir.to_str().unwrap());

    let config = Config::builder().with_provider(vault_provider).build();

    // Demonstrate secret interpolation
    println!("Configuration values after vault interpolation:");
    println!("===============================================");

    // Simple secret interpolation
    let server_secret: String = config.get("server.secret")?.unwrap();
    println!("server.secret: {}", server_secret);

    // Multiple secrets in one string
    let connection_string: String = config.get("database.connection_string")?.unwrap();
    println!("database.connection_string: {}", connection_string);

    // Secret in array
    let endpoints: Vec<String> = config.get("api.endpoints")?.unwrap();
    println!("api.endpoints: {:?}", endpoints);

    // Non-interpolated values pass through unchanged
    let log_level: String = config.get("logging.level")?.unwrap();
    println!("logging.level: {}", log_level);

    println!();
    println!("Example completed successfully!");

    Ok(())
}

#[cfg(not(feature = "vault-config"))]
fn main() {
    println!("This example requires the 'vault-config' feature to be enabled.");
    println!("Run with: cargo run --example vault_example --features vault-config");
}
