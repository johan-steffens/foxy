// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end integration tests for Foxy API Gateway

use foxy::Foxy;
use std::time::Duration;
use tokio::time::timeout;
use serial_test::serial;

mod common;
use common::{TestConfigProvider, init_test_logging};

#[tokio::test]
#[serial_test::serial]
async fn test_basic_proxy_functionality() {
    init_test_logging();

    // Use the example configuration file
    let foxy = Foxy::loader()
        .with_config_file("config/example.json")
        .build()
        .await
        .expect("Failed to build Foxy instance");

    // Start the proxy server in the background
    let server_handle = tokio::spawn(async move {
        foxy.start().await
    });

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make a request through the proxy to httpbin (configured in example.json)
    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(10),
        client.get("http://127.0.0.1:8080/").send()
    ).await;

    // Verify the response
    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            // The example config routes "/" to httpbin.org/get
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        },
        Ok(Err(e)) => panic!("Request failed: {}", e),
        Err(_) => panic!("Request timed out"),
    }

    // Clean up
    server_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_anything_endpoint() {
    init_test_logging();

    // Use the example configuration file
    let foxy = Foxy::loader()
        .with_config_file("config/example.json")
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move {
        foxy.start().await
    });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make request to httpbin anything endpoint (configured in example.json)
    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(10),
        client.get("http://127.0.0.1:8080/anything/test").send()
    ).await;

    // Verify the response
    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        },
        Ok(Err(e)) => panic!("Request failed: {}", e),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_post_method() {
    init_test_logging();

    // Use the example configuration file
    let foxy = Foxy::loader()
        .with_config_file("config/example.json")
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move {
        foxy.start().await
    });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make POST request (configured in example.json to route to /post)
    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(10),
        client.post("http://127.0.0.1:8080/").send()
    ).await;

    // Verify the response
    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        },
        Ok(Err(e)) => panic!("Request failed: {}", e),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_put_method() {
    init_test_logging();

    // Use the example configuration file
    let foxy = Foxy::loader()
        .with_config_file("config/example.json")
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move {
        foxy.start().await
    });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let client = reqwest::Client::new();

    // Test PUT / (should route to httpbin.org/put via path rewrite from example.json)
    let response = timeout(
        Duration::from_secs(10),
        client.put("http://127.0.0.1:8080/").send()
    ).await;

    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.unwrap();
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        },
        Ok(Err(e)) => panic!("Request failed: {}", e),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_method() {
    init_test_logging();

    // Use the example configuration file
    let foxy = Foxy::loader()
        .with_config_file("config/example.json")
        .build()
        .await
        .expect("Failed to build Foxy instance");

    let server_handle = tokio::spawn(async move {
        foxy.start().await
    });

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let client = reqwest::Client::new();

    // Test DELETE / (should route to httpbin.org/delete via path rewrite from example.json)
    let response = timeout(
        Duration::from_secs(10),
        client.delete("http://127.0.0.1:8080/").send()
    ).await;

    match response {
        Ok(Ok(resp)) => {
            assert_eq!(resp.status(), 200);
            let body = resp.text().await.expect("Failed to read body");
            assert!(body.contains("httpbin") || body.contains("origin") || body.contains("url"));
        },
        Ok(Err(e)) => panic!("Request failed: {}", e),
        Err(_) => panic!("Request timed out"),
    }

    server_handle.abort();

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;
}
