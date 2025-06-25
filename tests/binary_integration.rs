// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Integration tests for the Foxy binary CLI functionality.
//!
//! These tests validate the binary's behavior including:
//! - Configuration file loading from environment variables
//! - Fallback to default configuration paths
//! - Error handling for missing configuration files
//! - OpenTelemetry initialization
//! - Graceful startup and shutdown

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;
use serial_test::serial;
use tempfile::TempDir;
use tokio::time::{timeout, sleep};
use tokio::net::TcpStream;

/// Get the path to the foxy binary for the current platform
fn get_binary_path() -> &'static str {
    if cfg!(target_os = "windows") {
        "./target/debug/foxy.exe"
    } else {
        "./target/debug/foxy"
    }
}

mod common;
use common::init_test_logging;

/// Test configuration content for binary tests
const TEST_CONFIG_CONTENT: &str = r#"
[server]
host = "0.0.0.0"

[proxy]
timeout = 30

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;

/// Test configuration with OpenTelemetry enabled
const TEST_CONFIG_WITH_OTEL: &str = r#"
[server]
host = "0.0.0.0"

[proxy]
timeout = 30

[proxy.opentelemetry]
endpoint = "http://localhost:4317"
service_name = "foxy-test"

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;

/// Test configuration with empty OpenTelemetry endpoint
const TEST_CONFIG_WITH_EMPTY_OTEL: &str = r#"
[server]
host = "0.0.0.0"

[proxy]
timeout = 30

[proxy.opentelemetry]
endpoint = ""
service_name = "foxy-test"

[[proxy.routes]]
id = "test-route"
path_pattern = "/test"
target_base_url = "http://127.0.0.1:18081"
"#;

#[serial]
#[tokio::test]
async fn test_binary_with_default_config_path() {
    init_test_logging();

    // Build the binary first to avoid compilation time in the test
    let build_output = Command::new("cargo")
        .args(&["build", "--bin", "foxy"])
        .output()
        .expect("Failed to build foxy binary");

    if !build_output.status.success() {
        panic!("Failed to build binary: {}", String::from_utf8_lossy(&build_output.stderr));
    }

    let port = 18082;

    // We can't easily test the exact /etc/foxy/config.toml path without root access
    // So we'll test the error case when no config file is found
    let output = timeout(Duration::from_secs(3), async {
        Command::new(get_binary_path())
            .env("FOXY_SERVER_PORT", port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start foxy binary")
            .wait_with_output()
    }).await;

    match output {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Should indicate it's looking for default config and then exit with error
            assert!(
                stdout.contains("No FOXY_CONFIG_FILE env var found") ||
                stderr.contains("No FOXY_CONFIG_FILE env var found") ||
                stdout.contains("Default configuration file") ||
                stderr.contains("Default configuration file")
            );

            // Should exit with error code since no config file exists
            assert_ne!(output.status.code().unwrap_or(0), 0);
        }
        Ok(Err(e)) => {
            panic!("Failed to run binary: {}", e);
        }
        Err(_) => {
            panic!("Binary should exit quickly when no config file is found, but it timed out");
        }
    }
}

#[serial]
#[tokio::test]
async fn test_binary_missing_config_file_error() {
    init_test_logging();

    // Build the binary first to avoid compilation time in the test
    let build_output = Command::new("cargo")
        .args(&["build", "--bin", "foxy"])
        .output()
        .expect("Failed to build foxy binary");

    if !build_output.status.success() {
        panic!("Failed to build binary: {}", String::from_utf8_lossy(&build_output.stderr));
    }

    // Set environment variable to a non-existent file
    let non_existent_path = "/tmp/non_existent_config_file.toml";

    let port = 18083;

    let output = timeout(Duration::from_secs(3), async {
        Command::new(get_binary_path())
            .env("FOXY_SERVER_PORT", port.to_string())
            .env("FOXY_CONFIG_FILE", non_existent_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start foxy binary")
            .wait_with_output()
    }).await;

    match output {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Should indicate configuration file error
            assert!(
                stdout.contains("Failed to build proxy") ||
                stderr.contains("Failed to build proxy") ||
                output.status.code().unwrap_or(0) != 0
            );
        }
        Ok(Err(e)) => {
            panic!("Failed to run binary: {}", e);
        }
        Err(_) => {
            panic!("Binary should exit quickly with error, but it timed out");
        }
    }
}

#[serial]
#[tokio::test]
async fn test_binary_invalid_config_format() {
    init_test_logging();

    // Build the binary first to avoid compilation time in the test
    let build_output = Command::new("cargo")
        .args(&["build", "--bin", "foxy"])
        .output()
        .expect("Failed to build foxy binary");

    if !build_output.status.success() {
        panic!("Failed to build binary: {}", String::from_utf8_lossy(&build_output.stderr));
    }

    // Create a config file with invalid TOML
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("invalid_config.toml");
    fs::write(&config_path, "invalid toml content [[[").expect("Failed to write config file");

    let port = 18086;

    let output = timeout(Duration::from_secs(3), async {
        Command::new(get_binary_path())
            .env("FOXY_SERVER_PORT", port.to_string())
            .env("FOXY_CONFIG_FILE", config_path.to_str().unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start foxy binary")
            .wait_with_output()
    }).await;

    match output {
        Ok(Ok(output)) => {
            // Should fail with configuration error
            assert_ne!(output.status.code().unwrap_or(0), 0);

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                stdout.contains("Failed to build proxy") ||
                stderr.contains("Failed to build proxy")
            );
        }
        Ok(Err(e)) => {
            panic!("Failed to run binary: {}", e);
        }
        Err(_) => {
            panic!("Binary should exit quickly with error, but it timed out");
        }
    }
}

/// Helper function to wait for a TCP port to be open
async fn wait_for_port(addr: &str, timeout_duration: Duration) -> Result<(), String> {
    let start_time = tokio::time::Instant::now();
    while start_time.elapsed() < timeout_duration {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(format!("Timed out waiting for port {} to open", addr))
}
